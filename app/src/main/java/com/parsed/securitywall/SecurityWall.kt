package com.parsed.securitywall

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.net.VpnService
import android.os.Bundle
import android.os.IBinder
import android.util.Log
import android.view.View
import android.widget.ImageView
import android.widget.Switch
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity


class SecurityWall : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        try {
            this.supportActionBar!!.hide()
        } catch (e: NullPointerException) {}

        setContentView(R.layout.activity_main)
        val intent = VpnService.prepare(this@SecurityWall)
        if (intent != null) {
            startActivityForResult(intent, 0)
        } else {
            onActivityResult(0, Activity.RESULT_CANCELED, null)
        }
    }

    override fun onActivityResult(request: Int, result: Int, data: Intent?) {
        super.onActivityResult(request, result, data)
    }

    private fun getServiceIntent(): Intent {
        return Intent(this, SecurityService::class.java)
    }

    fun toggleProtection(toggleSwitch: View) {
        val toggleSwitch: Switch = toggleSwitch as Switch
        val statusView = this.findViewById<ImageView>(R.id.image_status);

        Log.d(TAG, "Toggling");
        if (toggleSwitch.isChecked()) {
            startService(getServiceIntent().setAction(SecurityService.ACTION_START))
            statusView.setImageResource(R.drawable.ic_lock);
        } else {
            startService(getServiceIntent().setAction(SecurityService.ACTION_STOP))
            statusView.setImageResource(R.drawable.ic_lock_open);
        }
    }

    private var mBoundService: SecurityService? = null
    private var mIsBound = false

    private val mConnection: ServiceConnection = object : ServiceConnection {
        override fun onServiceConnected(className: ComponentName, service: IBinder) {
            // This is called when the connection with the service has
            // been established, giving us the service object we can use
            // to interact with the service.  Because we have bound to a
            // explicit service that we know is running in our own
            // process, we can cast its IBinder to a concrete class and
            // directly access it.
            mBoundService = (service as SecurityService.LocalBinder).service

            // Tell the user about this for our demo.
            Toast.makeText(
                this@SecurityWall,
                "Connected to service",
                Toast.LENGTH_SHORT
            ).show()
        }

        override fun onServiceDisconnected(className: ComponentName) {
            // This is called when the connection with the service has
            // been unexpectedly disconnected -- that is, its process
            // crashed. Because it is running in our same process, we
            // should never see this happen.
            mBoundService = null
            Toast.makeText(
                this@SecurityWall,
                "Disconnected from service",
                Toast.LENGTH_SHORT
            ).show()
        }
    }

    fun doBindService() {
        bindService(
            Intent(this@SecurityWall, SecurityService::class.java),
            mConnection,
            Context.BIND_AUTO_CREATE
        )
        mIsBound = true
    }

    fun doUnbindService() {
        if (mIsBound) {
            // Detach our existing connection.
            unbindService(mConnection)
            mIsBound = false
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        doUnbindService()
    }

    companion object {
        val TAG = "SecurityUI";
    }
}