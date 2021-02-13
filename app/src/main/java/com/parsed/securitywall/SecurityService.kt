package com.parsed.securitywall

import android.app.*
import android.content.Intent
import android.net.VpnService
import android.os.*
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.databinding.ObservableBoolean
import com.viliussutkus89.android.tmpfile.Tmpfile
import java.io.*

class SecurityService : VpnService(), Handler.Callback {
    private var mSecurityFilter: SecurityFilter? = null
    private var mStatistics: SecurityStatistics? = null

    private val mBinder: IBinder = LocalBinder()
    inner class LocalBinder : Binder() {
        val service: SecurityService
        get() = this@SecurityService
    }

    private fun statsFile() = File(this.cacheDir.absolutePath + ".stats")
    private fun notificationManager() = getSystemService(
            android.content.Context.NOTIFICATION_SERVICE
        ) as android.app.NotificationManager

    override fun onCreate() {
        Tmpfile.init(applicationContext.cacheDir)
        mStatistics = SecurityStatistics.load(statsFile())
        notificationManager().createNotificationChannel(
            NotificationChannel(
                NOTIFICATION_CHANNEL_ID, NOTIFICATION_CHANNEL_ID,
                NotificationManager.IMPORTANCE_LOW
            )
        )
        Log.d(TAG, "Service Created")
    }

    private fun connect() {
        Log.d(TAG, "Starting SecurityFilter thread")
        mSecurityFilter = Util.readRawTextFile(this, R.raw.base)?.let { SecurityFilter(this, it) }
        mSecurityFilter!!.start()
        running.set(true)
        BootService.autostartOnBoot(this)
    }

    private fun disconnect() {
        Log.d(TAG, "Stopping SecurityFilter thread")
        if (mSecurityFilter != null) {
            Log.d(TAG, "Really stopping the thread")
            mSecurityFilter?.interrupt()
            while (mSecurityFilter?.isAlive == true) {
                Log.d(TAG, "Not finished yet")
            }
            mSecurityFilter = null
            running.set(false)
            Log.d(TAG, "Done")
        }
    }

    val running = ObservableBoolean()

    @RequiresApi(Build.VERSION_CODES.O)
    override fun onStartCommand(intent: Intent, flags: Int, startId: Int): Int {
        Log.d(TAG, "onStart")
        return if (ACTION_STOP == intent.action) {
            BootService.cancelOnBoot(this)
            disconnect()
            clearNotification()
            stopForeground(true)
            //stopSelf()
            Service.START_NOT_STICKY
        } else {
            Log.d(TAG, "connecting")
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
        mStatistics!!.totalTcp += newTcp
        mStatistics!!.totalUdp += newUdp
        mStatistics!!.totalBytesIn += newBytesIn
        mStatistics!!.totalBytesOut += newBytesOut
        mStatistics!!.trackersBlocked += newBlocked
        mStatistics!!.save(statsFile())

        Handler(Looper.getMainLooper()).postDelayed({
            running.notifyChange()
            updateForegroundNotification()
        }, 50)
    }

    fun currentConnections() = if (mSecurityFilter != null) mSecurityFilter!!.currentTcp + mSecurityFilter!!.currentUdp else 0
    fun sessionBlocked() = if (mSecurityFilter != null) mSecurityFilter!!.lastBlocked else 0
    fun sessionConnections() = if (mSecurityFilter != null) mSecurityFilter!!.lastTcp + mSecurityFilter!!.lastUdp else 0
    fun sessionBytes() = if (mSecurityFilter != null) mSecurityFilter!!.lastBytesIn + mSecurityFilter!!.lastBytesOut else 0

    fun totalBlocked() = if (mStatistics != null) mStatistics!!.trackersBlocked else 0
    fun totalConnections() = if (mStatistics != null) mStatistics!!.totalTcp + mStatistics!!.totalUdp else 0
    fun totalBytes() = if (mStatistics != null) mStatistics!!.totalBytesIn + mStatistics!!.totalBytesOut else 0

    private fun clearNotification() = notificationManager().cancel(1)
    private fun updateForegroundNotification() {
        val pending = Intent(this, SecurityService::class.java).setAction(ACTION_STOP)

        var action = Notification.Action.Builder(
            R.drawable.ic_lock_unlocked,
            getString(R.string.switch_off),
            PendingIntent.getService(this, 0, pending, 0)
        ).build()

        val openApp = Intent(this, SecurityWall::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }

        val contentIntent = PendingIntent.getActivity(
            this, 0, openApp, PendingIntent.FLAG_UPDATE_CURRENT
        )

        var bigTextStyle = Notification.BigTextStyle().bigText(
            getString(R.string.life_blocked_trackers) + " " + mStatistics!!.trackersBlocked + "\n" + getString(
                R.string.monitored
            ) + " " + currentConnections() + "\n" + getString(R.string.life_monitored) + " " + mStatistics!!.totalConnections()
        )

        val notification = Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat)
            .setStyle(bigTextStyle)
            .setContentTitle(getString(R.string.blocked_trackers) + " " + sessionBlocked())
            .setContentIntent(contentIntent)
            .addAction(action)
            .setOngoing(true)
            .build()

        notificationManager().notify(1, notification)
    }

    companion object {
        const val TAG = "SecurityService"
        const val ACTION_START = "com.parsed.securitywall.START"
        const val ACTION_STOP = "com.parsed.securitywall.STOP"
        const val NOTIFICATION_CHANNEL_ID = "SecurityWall"
    }
}