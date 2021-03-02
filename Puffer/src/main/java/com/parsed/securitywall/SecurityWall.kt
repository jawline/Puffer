package com.parsed.securitywall

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.net.Uri
import android.net.VpnService
import android.os.Bundle
import android.os.IBinder
import android.util.Log
import android.util.TypedValue
import android.view.View
import android.widget.ImageView
import android.widget.Switch
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.databinding.Observable
import androidx.databinding.Observable.OnPropertyChangedCallback


class SecurityWall : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        try {
            this.supportActionBar!!.hide()
        } catch (e: NullPointerException) {
        }

        setContentView(R.layout.activity_main)

        val intent = VpnService.prepare(this@SecurityWall)
        if (intent != null) {
            startActivityForResult(intent, 0)
        } else {
            onActivityResult(0, Activity.RESULT_OK, null)
        }
    }

    // If the user does not consent then close the application
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode != Activity.RESULT_OK) {
            finish()
            return
        }
        bindSecurityService()
    }


    private fun getSecurityServiceIntent(ctx: Context): Intent =
        Intent(ctx, SecurityService::class.java)

    private fun startSecurityService(ctx: Context) =
        ctx.startService(getSecurityServiceIntent(ctx).setAction(SecurityService.ACTION_START))

    private fun stopSecurityService(ctx: Context) =
        ctx.startService(getSecurityServiceIntent(ctx).setAction(SecurityService.ACTION_STOP))

    fun toggleProtection(toggleSwitch: View) {
        toggleSwitch as Switch
        Log.d(TAG, "Toggling")
        if (toggleSwitch.isChecked) {
            startSecurityService(this)
        } else {
            stopSecurityService(this)
        }
    }

    private var mSecurityService: SecurityService? = null

    private fun extract(attr: Int): Int {
        val typedValue = TypedValue()
        theme.resolveAttribute(attr, typedValue, true)
        val imageResId = typedValue.resourceId
        return imageResId
    }

    fun updateToggle() {
        val statusText = this.findViewById<TextView>(R.id.status_text)
        val statusView = this.findViewById<ImageView>(R.id.status_image)
        val toggleSwitch = findViewById<Switch>(R.id.status_toggle)

        val isChecked = if (mSecurityService != null) mSecurityService!!.running.get() else {
            false
        }
        toggleSwitch.isChecked = isChecked
        toggleSwitch.isEnabled = true

        if (isChecked) {
            statusText.setText(R.string.user_protected)
            statusView.setImageResource(extract(R.attr.awake))
        } else {
            statusText.setText(R.string.user_unprotected)
            statusView.setImageResource(extract(R.attr.sleeping))
        }
    }

    fun updateStatistics() {
        if (mSecurityService != null) {
            this.findViewById<TextView>(R.id.current_connections).text =
                "" + mSecurityService!!.currentConnections()
            //this.findViewById<TextView>(R.id.session_blocked).text =
            //    "" + mSecurityService!!.sessionBlocked()
            //this.findViewById<TextView>(R.id.session_connections).text =
            //    "" + mSecurityService!!.sessionConnections()
            //this.findViewById<TextView>(R.id.session_bytes).text =
            //    "" + bytesToString(mSecurityService!!.sessionBytes())

            this.findViewById<TextView>(R.id.total_blocked).text =
                "" + mSecurityService!!.totalBlocked()
            this.findViewById<TextView>(R.id.total_connections).text =
                "" + mSecurityService!!.totalConnections()
            this.findViewById<TextView>(R.id.total_bytes).text =
                "" + bytesToString(mSecurityService!!.totalBytes())
        }
    }

    private var serviceWatcher = object : OnPropertyChangedCallback() {
        override fun onPropertyChanged(sender: Observable?, propertyId: Int) {
            updateToggle()
            updateStatistics()
        }
    }

    private val mSecurityServiceBinding: ServiceConnection = object : ServiceConnection {
        override fun onServiceConnected(className: ComponentName, service: IBinder) {
            mSecurityService = (service as SecurityService.LocalBinder).service
            mSecurityService!!.running.addOnPropertyChangedCallback(serviceWatcher)
            updateToggle()
            updateStatistics()
        }

        override fun onServiceDisconnected(className: ComponentName) {
            mSecurityService!!.running.removeOnPropertyChangedCallback(serviceWatcher)
            mSecurityService = null
        }
    }

    fun bindSecurityService() {
        if (mSecurityService == null) {
            bindService(
                Intent(this@SecurityWall, SecurityService::class.java),
                mSecurityServiceBinding,
                Context.BIND_AUTO_CREATE
            )
        }
    }

    fun unbindSecurityService() {
        if (mSecurityService != null) {
            unbindService(mSecurityServiceBinding)
            mSecurityService = null
        }
    }

    fun showLiveView(_btn: View) {
        val liveView = Intent(this, LiveView::class.java)
        startActivity(liveView)
    }

    fun showSettings(_btn: View) {
        val settingsActivity = Intent(this, SettingsActivity::class.java)
        startActivity(settingsActivity)
    }

    fun testAdblocker(_btn: View) {
        val browserIntent =
            Intent(Intent.ACTION_VIEW, Uri.parse("https://ads-blocker.com/testing/"))
        startActivity(browserIntent)
    }

    override fun onDestroy() {
        super.onDestroy()
        unbindSecurityService()
    }

    companion object {
        val TAG = "SecurityUI"
        fun bytesToString(bytes: Long) = when {
            bytes == Long.MIN_VALUE || bytes < 0 -> "N/A"
            bytes < 1024L -> "$bytes B"
            bytes <= 0xfffccccccccccccL shr 40 -> "%.1f KiB".format(bytes.toDouble() / (0x1 shl 10))
            bytes <= 0xfffccccccccccccL shr 30 -> "%.1f MiB".format(bytes.toDouble() / (0x1 shl 20))
            bytes <= 0xfffccccccccccccL shr 20 -> "%.1f GiB".format(bytes.toDouble() / (0x1 shl 30))
            bytes <= 0xfffccccccccccccL shr 10 -> "%.1f TiB".format(bytes.toDouble() / (0x1 shl 40))
            bytes <= 0xfffccccccccccccL -> "%.1f PiB".format((bytes shr 10).toDouble() / (0x1 shl 40))
            else -> "%.1f EiB".format((bytes shr 20).toDouble() / (0x1 shl 40))
        }
    }
}