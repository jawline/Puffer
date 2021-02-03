package com.parsed.securitywall

import android.app.*
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.*
import android.util.Log
import androidx.annotation.RequiresApi
import java.io.BufferedReader
import java.io.IOException
import java.io.InputStream
import java.io.InputStreamReader

class SecurityService : VpnService(), Handler.Callback {
    private var mHandler: Handler? = null
    private var mConfigureIntent: PendingIntent? = null
    private var mFilterThread: Thread? = null
    private var mSecurityFilter: SecurityFilter? = null

    // This is the object that receives interactions from clients.
    private val mBinder: IBinder = LocalBinder()

    inner class LocalBinder : Binder() {
        val service: SecurityService
        get() = this@SecurityService
    }

    override fun onCreate() {
        if (mHandler == null) {
            mHandler = Handler(this)
        }
        mConfigureIntent = PendingIntent.getActivity(
            this, 0, Intent(this, SecurityWall::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT
        )
        Log.d(TAG, "Service Created")
    }

    fun connect() {
        Log.d(TAG, "Starting SecurityFilter thread")
        mSecurityFilter = SecurityFilter(this, readRawTextFile(this, R.raw.base))
        mFilterThread = Thread(mSecurityFilter, "SecurityFilter")
        mFilterThread!!.start()
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
            Log.d(TAG, "Done");
        }
    }

    @RequiresApi(Build.VERSION_CODES.O)
    override fun onStartCommand(intent: Intent, flags: Int, startId: Int): Int {
        Log.d(TAG, "onStart")
        return if (ACTION_STOP == intent.action) {
            disconnect()
            stopForeground(true)
            //stopSelf()
            Service.START_NOT_STICKY
        } else {
            Log.d(TAG, "connecting")
            connect()
            updateForegroundNotification(1)
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
        disconnect()
    }

    @RequiresApi(Build.VERSION_CODES.O)
    private fun updateForegroundNotification(message: Int) {
        val NOTIFICATION_CHANNEL_ID = "SecurityWall"

        val mNotificationManager = getSystemService(
            Context.NOTIFICATION_SERVICE
        ) as NotificationManager

        mNotificationManager.createNotificationChannel(
            NotificationChannel(
                NOTIFICATION_CHANNEL_ID, NOTIFICATION_CHANNEL_ID,
                NotificationManager.IMPORTANCE_DEFAULT
            )
        )

        val notification = Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentText("Securing your connection")
            .setContentIntent(mConfigureIntent)
            .build()

        startForeground(
            1,
            notification
        )
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