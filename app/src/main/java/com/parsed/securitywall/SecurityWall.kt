package com.parsed.securitywall

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity

class SecurityWall : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val intent = VpnService.prepare(this@SecurityWall)
        if (intent != null) {
            startActivityForResult(intent, 0)
        } else {
            onActivityResult(0, Activity.RESULT_OK, null)
        }
    }

    override fun onActivityResult(request: Int, result: Int, data: Intent?) {
        super.onActivityResult(request, result, data)
        System.out.printf("Activity Result: %d, %d EXPECTED %d\n", request, result, Activity.RESULT_OK)
        if (result == Activity.RESULT_OK) {
            startService(getServiceIntent().setAction(SecurityService.ACTION_START))
        } else {

        }
    }

    private fun getServiceIntent(): Intent {
        return Intent(this, SecurityService::class.java)
    }
}