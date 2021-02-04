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
import androidx.appcompat.app.AppCompatActivity
import androidx.databinding.Observable
import androidx.databinding.Observable.OnPropertyChangedCallback


class SecurityWall : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        try {
            this.supportActionBar!!.hide()
        } catch (e: NullPointerException) {}
        setContentView(R.layout.activity_main)

        doBindService()

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

    fun updateToggle() {
        val toggleSwitch = findViewById<Switch>(R.id.enable_switch);
        toggleSwitch.isChecked = mBoundService!!.running.get();
    }

    private var watcher = object: OnPropertyChangedCallback() {
        override fun onPropertyChanged(sender: Observable?, propertyId: Int) {
            updateToggle()
        }
    }

    private val mConnection: ServiceConnection = object : ServiceConnection {
        override fun onServiceConnected(className: ComponentName, service: IBinder) {
            mBoundService = (service as SecurityService.LocalBinder).service
            mBoundService!!.running.addOnPropertyChangedCallback(watcher)
            updateToggle()
        }

        override fun onServiceDisconnected(className: ComponentName) {
            mBoundService!!.running.removeOnPropertyChangedCallback(watcher)
            mBoundService = null
        }
    }

    fun doBindService() {
        if (mBoundService == null) {
            bindService(
                Intent(this@SecurityWall, SecurityService::class.java),
                mConnection,
                Context.BIND_AUTO_CREATE
            )
        }
    }

    fun doUnbindService() {
        if (mBoundService != null) {
            unbindService(mConnection)
            mBoundService = null
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