package com.parsed.securitywall

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.IBinder
import android.view.View
import android.widget.LinearLayout
import android.widget.TableLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.databinding.Observable
import com.google.android.material.tabs.TabLayout
import com.google.android.material.tabs.TabLayout.OnTabSelectedListener


class LiveView : AppCompatActivity() {
    private var mSecurityService: SecurityService? = null
    private var mLiveView: View? = null
    private var mBlockView: View? = null
    private var mCurrentView: View? = null

    fun rootView() = findViewById<LinearLayout>(R.id.analysis_root)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        bindSecurityService()

        try {
            this.supportActionBar!!.hide()
        } catch (e: NullPointerException) {
        }

        setContentView(R.layout.analysis_view)

        mLiveView = View.inflate(this, R.layout.live_view, null)
        mBlockView = View.inflate(this, R.layout.block_view, null)

        val tabs = findViewById<TabLayout>(R.id.tabLayout)
        val blockedTab = tabs.newTab().setText("Blocked")
        val liveTab = tabs.newTab().setText("Live")
        tabs.addTab(blockedTab)
        tabs.addTab(liveTab)
        tabs.setTabGravity(TabLayout.GRAVITY_FILL)

        fun select(tab: TabLayout.Tab) {
            if (mCurrentView != null) {
                rootView().removeView(mCurrentView)
            }
            mCurrentView = when (tab) {
                liveTab -> mLiveView
                else -> {
                    mBlockView
                }
            }

            if (mCurrentView != null) {
                rootView().addView(mCurrentView)
            }
        }

        select(blockedTab)

        tabs.addOnTabSelectedListener(object : OnTabSelectedListener {
            override fun onTabSelected(tab: TabLayout.Tab) {
                select(tab)
            }

            override fun onTabUnselected(tab: TabLayout.Tab) {}
            override fun onTabReselected(tab: TabLayout.Tab) {}
        })
    }

    fun add(table: TableLayout, sni: String, ip: String, port: String) {

        val childLayout = View.inflate(this, R.layout.live_view_item, null)
        childLayout.findViewById<TextView>(R.id.sni).text = sni
        childLayout.findViewById<TextView>(R.id.ip).text = ip
        // childLayout.findViewById<TextView>(R.id.port).text = port

        table.addView(childLayout)
    }

    override fun onDestroy() {
        super.onDestroy()
        unbindSecurityService()
    }

    fun update() {
        if (mSecurityService != null) {
            val liveTbl = mLiveView!!.findViewById<TableLayout>(R.id.live_view_tbl)
            liveTbl.removeAllViews()

            for (conn in mSecurityService!!.mCurrentConns) {
                add(liveTbl, conn.sni, conn.ip, conn.port.toString())
            }

            val blockTbl = mBlockView!!.findViewById<TableLayout>(R.id.live_view_tbl)
            blockTbl.removeAllViews()

            val blockList = mSecurityService!!.mSessionBlocked

            for (blocks in blockList.toSortedMap(compareBy { -blockList[it]!! })) {
                add(blockTbl, blocks.key, blocks.value.toString(), "")
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