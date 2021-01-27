package com.parsed.securitywall

import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.annotation.RequiresApi
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer

class SecurityFilter(service: SecurityService): Runnable{

    companion object {
        const val TAG = "sec_filter"
    }

    val mService = service;
    var interfaceFileDescriptor: ParcelFileDescriptor? = null;

    @RequiresApi(Build.VERSION_CODES.LOLLIPOP)
    override fun run() {
        val vpnBuilder = mService.Builder();

        Log.i(TAG,"Starting SecurityFilter")

        vpnBuilder.addDisallowedApplication("com.parsed.securitywall")
        vpnBuilder.addAddress("10.125.0.6", 24)
        vpnBuilder.addRoute("0.0.0.0", 0)
        vpnBuilder.setMtu(1500)

        Log.d(TAG, "Configured Builder")

        synchronized (mService) {
            interfaceFileDescriptor = vpnBuilder.establish()
        }

        Log.d(TAG,"Estabished")

        val tunIn = FileInputStream(interfaceFileDescriptor!!.getFileDescriptor())
        val tunOut = FileOutputStream(interfaceFileDescriptor!!.getFileDescriptor())

        val packet = ByteBuffer.allocate(1500)

        while(true) {
            val length = tunIn.read(packet.array())
            if (length > 0) {
                tunOut.write(packet.array(), 0, length)
                Log.d(TAG, "Packet: " + length)
            }
        }
    }
}