package com.parsed.securitywall

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Switch
import androidx.appcompat.app.AppCompatActivity
import androidx.preference.PreferenceManager


class SettingsActivity: AppCompatActivity() {
    var settings: Settings? = null

    class Settings(context: Context) {
        private val preferences = PreferenceManager.getDefaultSharedPreferences(context)

        var blockUpnp: Boolean
            get() = preferences.getBoolean(BLOCK_UPNP, false)
            set(value) {
                val editor = preferences.edit()
                editor.putBoolean(BLOCK_UPNP, value)
                editor.apply()
            }

        var blockLan: Boolean
            get() = preferences.getBoolean(BLOCK_LAN, false)
            set(value) {
                val editor = preferences.edit()
                editor.putBoolean(BLOCK_LAN, value)
                editor.apply()
            }

        val nativeBlockMode: Int
            get() = if (blockLan) { 2 } else if (blockUpnp) { 1 } else { 0 }

        companion object {
            val BLOCK_UPNP: String = "upnp_disabled"
            val BLOCK_LAN: String = "lan_disabled"
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.settings_view)

        try {
            this.supportActionBar!!.hide()
        } catch (e: NullPointerException) {}

        settings = Settings(this)

        findViewById<Switch>(R.id.tgl_block_upnp).isChecked = settings!!.blockUpnp
        findViewById<Switch>(R.id.tgl_block_lan).isChecked = settings!!.blockLan
        checkIfLanForcesUpnp()
    }

    fun onBlockUpnpToggle(view: View) {
        // Don't modify the setting if the LAN option is checked (it supercedes this)
        if (!settings!!.blockLan) {
            settings!!.blockUpnp = (view as Switch).isChecked
            Log.d(TAG, "Set UPnP to " + view.isChecked)
        }
    }

    fun onBlockLANToggle(view: View) {
        settings!!.blockLan = (view as Switch).isChecked
        Log.d(TAG, "Set LAN to " + view.isChecked)
        checkIfLanForcesUpnp()
    }

    fun launchBlocklists(_view: View) {
        val blockList = Intent(this, BlockListActivity::class.java)
        startActivity(blockList)
    }

    fun checkIfLanForcesUpnp() {
        if (settings!!.blockLan) {
            findViewById<Switch>(R.id.tgl_block_upnp).isChecked = true
            findViewById<Switch>(R.id.tgl_block_upnp).isEnabled = false
        } else {
            findViewById<Switch>(R.id.tgl_block_upnp).isChecked = settings!!.blockUpnp
            findViewById<Switch>(R.id.tgl_block_upnp).isEnabled = true
        }
    }

    companion object {
        val TAG: String = "Settings"
    }
}