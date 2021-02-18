package com.parsed.securitywall

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.IBinder
import android.view.View
import android.widget.TableLayout
import android.widget.TextView
import androidx.databinding.Observable

class LiveView: Activity() {
    private var mSecurityService: SecurityService? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        bindSecurityService()
    }

    fun add(sni: String, ip: String, port: String) {

        val childLayout = View.inflate(this, R.layout.live_view_item, null)
        childLayout.findViewById<TextView>(R.id.sni).text = sni
        childLayout.findViewById<TextView>(R.id.ip).text = ip
        // childLayout.findViewById<TextView>(R.id.port).text = port

        val tbl = findViewById<TableLayout>(R.id.live_view_tbl)
        tbl.addView(childLayout)
    }

    override fun onDestroy() {
        super.onDestroy()
        unbindSecurityService()
    }

    fun update() {
        setContentView(R.layout.live_view)
        if (mSecurityService != null) {
            for (conn in mSecurityService!!.mCurrentConns) {
                add(conn.sni, conn.ip, conn.port.toString())
            }
        }
    }

    private var serviceWatcher = object : Observable.OnPropertyChangedCallback() {
        override fun onPropertyChanged(sender: Observable?, propertyId: Int) {
            update()
        }
    }

    private val mSecurityServiceBinding: ServiceConnection = object : ServiceConnection {
        override fun onServiceConnected(className: ComponentName, service: IBinder) {
            mSecurityService = (service as SecurityService.LocalBinder).service
            mSecurityService!!.reported.addOnPropertyChangedCallback(serviceWatcher)
            update()
        }

        override fun onServiceDisconnected(className: ComponentName) {
            mSecurityService!!.reported.removeOnPropertyChangedCallback(serviceWatcher)
            mSecurityService = null
        }
    }

    fun bindSecurityService() {
        if (mSecurityService == null) {
            bindService(
                Intent(this@LiveView, SecurityService::class.java),
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

}