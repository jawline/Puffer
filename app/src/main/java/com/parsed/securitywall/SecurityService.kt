package com.parsed.securitywall

import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.net.VpnService
import android.os.Handler
import android.os.Message
import android.util.Log

class SecurityService : VpnService(), Handler.Callback {
    private var mHandler: Handler? = null
    private var mConfigureIntent: PendingIntent? = null
    private var mFilterThread: Thread? = null

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
        mFilterThread = Thread(SecurityFilter(this), "SecurityFilter")
        mFilterThread!!.start()
    }

    fun disconnect() {
        Log.d(TAG, "Stopping SecurityFilter thread")
        if (mFilterThread != null) {
            mFilterThread!!.interrupt()
            mFilterThread = null
        }
    }

    override fun onStartCommand(intent: Intent, flags: Int, startId: Int): Int {
        Log.d(TAG, "onStart")
        return if (intent != null && ACTION_STOP == intent.action) {
            disconnect()
            Service.START_NOT_STICKY
        } else {
            Log.d(TAG, "connecting")
            connect()
            Service.START_STICKY
        }
    }

    override fun handleMessage(msg: Message): Boolean {
        return false
    }

    companion object {
        const val TAG = "SecurityService"
        const val ACTION_START = "com.parsed.securitywall.START"
        const val ACTION_STOP = "com.parsed.securitywall.STOP"
    }
}