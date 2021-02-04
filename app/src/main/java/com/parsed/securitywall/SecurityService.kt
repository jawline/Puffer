package com.parsed.securitywall

import android.app.*
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.*
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.core.app.NotificationCompat
import androidx.databinding.ObservableBoolean
import com.viliussutkus89.android.tmpfile.Tmpfile
import java.io.BufferedReader
import java.io.IOException
import java.io.InputStream
import java.io.InputStreamReader

class SecurityService : VpnService(), Handler.Callback {
    private var mHandler: Handler? = null
    private var mConfigureIntent: PendingIntent? = null
    private var mFilterThread: Thread? = null
    private var mSecurityFilter: SecurityFilter? = null
    private var mNotificationManager: NotificationManager? = null

    // This is the object that receives interactions from clients.
    private val mBinder: IBinder = LocalBinder()

    inner class LocalBinder : Binder() {
        val service: SecurityService
        get() = this@SecurityService
    }

    override fun onCreate() {
        Tmpfile.init(getApplicationContext().getCacheDir());
        if (mHandler == null) {
            mHandler = Handler(this)
        }
        mConfigureIntent = PendingIntent.getActivity(
            this, 0, Intent(this, SecurityWall::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT
        )
        mNotificationManager = getSystemService(
                android.content.Context.NOTIFICATION_SERVICE
                ) as android.app.NotificationManager
        Log.d(TAG, "Service Created")
    }

    fun connect() {
        Log.d(TAG, "Starting SecurityFilter thread")
        mSecurityFilter = readRawTextFile(this, R.raw.base)?.let { SecurityFilter(this, it) }
        mFilterThread = Thread(mSecurityFilter, "SecurityFilter")
        mFilterThread!!.start()
        running.set(true)
    }

    fun disconnect() {
        Log.d(TAG, "Stopping SecurityFilter thread")
        if (mFilterThread != null) {
            Log.d(TAG, "Really stopping the thread");
            mSecurityFilter?.interrupt()
            mFilterThread!!.interrupt()
            while (mFilterThread?.isAlive() == true) {
                Log.d(TAG, "Not finished yet")
            }
            mFilterThread = null
            mSecurityFilter = null
            running.set(false)
            Log.d(TAG, "Done");
        }
    }

    val running = ObservableBoolean()

    @RequiresApi(Build.VERSION_CODES.O)
    override fun onStartCommand(intent: Intent, flags: Int, startId: Int): Int {
        Log.d(TAG, "onStart")
        return if (ACTION_STOP == intent.action) {
            disconnect()
            clearNotification()
            stopForeground(true)
            //stopSelf()
            Service.START_NOT_STICKY
        } else {
            Log.d(TAG, "connecting")
            connect()
            updateForegroundNotification(0,0,0)
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
        disconnect()
    }

    var first = true;

    fun clearNotification() {
        mNotificationManager!!.cancel(1)
    }

    public fun updateForegroundNotification(total_current: Int, total_session: Int, blocked_count: Int) {
        val NOTIFICATION_CHANNEL_ID = "SecurityWall"

        if (first) {
            mNotificationManager!!.createNotificationChannel(
                NotificationChannel(
                    NOTIFICATION_CHANNEL_ID, NOTIFICATION_CHANNEL_ID,
                    NotificationManager.IMPORTANCE_MIN
                )
            )
            first = false
        }

        val pending = Intent(this, SecurityService::class.java).setAction(ACTION_STOP)
        var action = Notification.Action.Builder(R.drawable.ic_lock_open, getString(R.string.switch_off), PendingIntent.getService(this, 0, pending, 0)).build()

        var bigTextStyle = Notification.BigTextStyle().bigText(getString(R.string.monitored) + " " + total_current +"\n" + getString(R.string.life_monitored) + " " + total_session)

        val notification = Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setStyle(bigTextStyle)
            .setContentTitle(getString(R.string.blocked_trackers) + " " + blocked_count)
            .addAction(action)
            .setOngoing(true)
            .build()

        mNotificationManager!!.notify(1, notification)
    }

    fun readRawTextFile(ctx: Context, resId: Int): String? {
        val inputStream: InputStream = ctx.resources.openRawResource(resId)
        val inputreader = InputStreamReader(inputStream)
        val buffreader = BufferedReader(inputreader)
        var line: String? = null
        val text = StringBuilder()
        try {
            while (buffreader.readLine().also({ line = it }) != null) {
                text.append(line)
                text.append('\n')
            }
        } catch (e: IOException) {
            return null
        }
        return text.toString()
    }

    companion object {
        const val TAG = "SecurityService"
        const val ACTION_START = "com.parsed.securitywall.START"
        const val ACTION_STOP = "com.parsed.securitywall.STOP"
    }
}