package com.parsed.securitywall

import android.app.*
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.*
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.databinding.ObservableBoolean
import com.viliussutkus89.android.tmpfile.Tmpfile
import java.io.*
import java.util.*
import kotlin.collections.ArrayList
import kotlin.collections.HashMap

class SecurityService : VpnService(), Handler.Callback {
    private var mSecurityFilter: SecurityFilter? = null
    private var mStatistics: SecurityStatistics? = null
    private var mTimer: Timer? = null
    private var mPaused = false

    val mCurrentConns = ArrayList<ConnectionInfo>()
    val mSessionBlocked = HashMap<String, Long>()

    private val mBinder: IBinder = LocalBinder()

    inner class LocalBinder : Binder() {
        val service: SecurityService
            get() = this@SecurityService
    }

    private fun statsFile() = File(this.cacheDir.absolutePath + ".stats")
    private fun notificationManager() = NotificationManagerCompat.from(this)

    override fun onCreate() {
        Tmpfile.init(applicationContext.cacheDir)
        mStatistics = SecurityStatistics.load(statsFile())

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            notificationManager().createNotificationChannel(
                NotificationChannel(
                    NOTIFICATION_CHANNEL_ID, NOTIFICATION_CHANNEL_ID,
                    NotificationManager.IMPORTANCE_MIN
                )
            )
        }
        Log.d(TAG, "Service Created")
    }

    private fun connect() {
        Log.d(TAG, "Starting SecurityFilter thread")

        val blockListBase = Util.readRawTextFile(this, R.raw.base)!!
        val blockListAddition = BlockListActivity.block(this).asString()
        val allowList = BlockListActivity.allow(this).asString()

        Log.d(TAG, "Additional: $blockListAddition")

        mSecurityFilter = SecurityFilter(this, blockListBase + blockListAddition, allowList)
        mSecurityFilter!!.start()
        running.set(true)
    }

    private fun disconnect() {
        Log.d(TAG, "Stopping SecurityFilter thread")
        if (mSecurityFilter != null) {
            Log.d(TAG, "Really stopping the thread")
            mSecurityFilter?.interrupt()
            while (mSecurityFilter?.isAlive == true) {}
            Log.d(TAG, "Done")
        }
    }

    val running = ObservableBoolean()
    val reported = ObservableBoolean()

    fun clearPause() {
        mPaused = false

        val timer = mTimer
        if (timer != null) {
            timer.cancel()
            mTimer = null
        }
    }

    class PauseTimerExpired(mContext: Context): TimerTask() {
        private val mContext = mContext
        override fun run() {
            val resumeIntent = Intent(mContext, SecurityService::class.java).setAction(ACTION_START)
            mContext.startService(resumeIntent)
        }
    }

    fun setupPause() {

        //Clear any existing pause (just in case, should be impossible)
        clearPause()

        // Set up the new one
        mTimer = Timer()
        mTimer!!.schedule(PauseTimerExpired(this), THIRTY_MINUTES)

        mPaused = true
    }

    override fun onStartCommand(intent: Intent, flags: Int, startId: Int): Int {
        Log.d(TAG, "onStart")
        return if (ACTION_STOP == intent.action) {
            clearPause()
            disconnect()
            Service.START_NOT_STICKY
        } else if (ACTION_PAUSE == intent.action) {

            // No action if the app is already paused or is off (just to prevent races with other threads / async events)
            if (mPaused || mSecurityFilter == null) {
                return Service.START_STICKY;
            }

            Log.d(TAG, "Pausing")
            setupPause()
            disconnect()
            Service.START_STICKY
        } else {
            Log.d(TAG, "connecting")
            clearPause()

            // We are still running - do nothing (Should not happen if resume button and timers are correctly self-cancelling)
            if (mSecurityFilter != null) {
                return Service.START_STICKY
            }

            connect()
            updateForegroundNotification()
            Service.START_STICKY
        }
    }

    override fun handleMessage(msg: Message): Boolean {
        return false
    }

    override fun onBind(intent: Intent?): IBinder? {
        return mBinder
    }

    override fun onDestroy() {
        clearNotification()
    }

    fun report(newTcp: Long, newUdp: Long, newBytesIn: Long, newBytesOut: Long, newBlocked: Long) {
        if (mStatistics != null) {
            mStatistics!!.totalTcp += newTcp
            mStatistics!!.totalUdp += newUdp
            mStatistics!!.totalBytesIn += newBytesIn
            mStatistics!!.totalBytesOut += newBytesOut
            mStatistics!!.trackersBlocked += newBlocked
            mStatistics!!.save(statsFile())
        }
        mCurrentConns.clear() // Clear all conns each report the C portion will re-send
    }

    fun reportConn(info: ConnectionInfo) {
        mCurrentConns.add(info)
    }

    fun reportBlock(name: String) {
        val timesBlocked = (mSessionBlocked[name] ?: 0) + 1
        mSessionBlocked[name] = timesBlocked
    }

    fun finalizeShutdown() {
        Handler(Looper.getMainLooper()).postDelayed({
            running.set(false)
            reported.notifyChange()
            
            mSecurityFilter = null

            // If we are paused then we display a different notification otherwise we clear notifications on shutdown
            if (!mPaused) {
                clearNotification()
            } else {
                updateForegroundNotification()
            }
        }, 50)
    }

    fun reportFinished() {
        Handler(Looper.getMainLooper()).postDelayed({
            running.notifyChange()
            reported.notifyChange()
            updateForegroundNotification()
        }, 50)
    }

    fun currentConnections() =
        if (mSecurityFilter != null) mSecurityFilter!!.currentTcp + mSecurityFilter!!.currentUdp else 0

    fun sessionBlocked() = if (mSecurityFilter != null) mSecurityFilter!!.lastBlocked else 0
    fun sessionConnections() =
        if (mSecurityFilter != null) mSecurityFilter!!.lastTcp + mSecurityFilter!!.lastUdp else 0

    fun sessionBytes() =
        if (mSecurityFilter != null) mSecurityFilter!!.lastBytesIn + mSecurityFilter!!.lastBytesOut else 0

    fun totalBlocked() = if (mStatistics != null) mStatistics!!.trackersBlocked else 0
    fun totalConnections() =
        if (mStatistics != null) mStatistics!!.totalTcp + mStatistics!!.totalUdp else 0

    fun totalBytes() =
        if (mStatistics != null) mStatistics!!.totalBytesIn + mStatistics!!.totalBytesOut else 0

    private fun clearNotification() = stopForeground(true)

    private fun updateForegroundNotification() {

        var actions: ArrayList<NotificationCompat.Action> = ArrayList()

        if (!mPaused) {
            val switchOffIntent = Intent(this, SecurityService::class.java).setAction(ACTION_STOP)

            var switchOffAction = NotificationCompat.Action.Builder(
                R.drawable.ic_sleeping_light,
                getString(R.string.switch_off),
                PendingIntent.getService(this, 0, switchOffIntent, 0)
            ).build()

            val pauseIntent = Intent(this, SecurityService::class.java).setAction(ACTION_PAUSE)

            var pauseAction = NotificationCompat.Action.Builder(
                R.drawable.ic_sleeping_light,
                getString(R.string.pause),
                PendingIntent.getService(this, 0, pauseIntent, 0)
            ).build()

            actions.add(pauseAction)
            actions.add(switchOffAction)
        } else {
            val resumeIntent = Intent(this, SecurityService::class.java).setAction(ACTION_START)
            var resumeAction = NotificationCompat.Action.Builder(
                R.drawable.ic_sleeping_light,
                getString(R.string.resume),
                PendingIntent.getService(this, 0, resumeIntent, 0)
            ).build()
            actions.add(resumeAction)
        }

        val openApp = Intent(this, SecurityWall::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }

        val contentIntent = PendingIntent.getActivity(
            this, 0, openApp, PendingIntent.FLAG_UPDATE_CURRENT
        )

        val bigTextStyle = NotificationCompat.BigTextStyle().bigText(
            getString(
                R.string.monitored
            ) + " " + currentConnections() + "\n" + getString(R.string.life_monitored) + " " + totalConnections()
        )

        var notification = NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat)
            .setStyle(bigTextStyle)
            .setContentTitle(getString(R.string.blocked_trackers) + " " + sessionBlocked())
            .setContentIntent(contentIntent);

        for (action in actions) {
            notification = notification.addAction(action)
        }

        notification = notification.setOngoing(true)

        startForeground(1, notification.build())
    }

    companion object {
        const val TAG = "SecurityService"
        const val ACTION_START = "com.parsed.securitywall.START"
        const val ACTION_STOP = "com.parsed.securitywall.STOP"
        const val ACTION_PAUSE = "com.parsed.securitywall.PAUSE"
        const val NOTIFICATION_CHANNEL_ID = "SecurityWall"
        const val THIRTY_MINUTES: Long = 1000 * 60 * 30
    }
}