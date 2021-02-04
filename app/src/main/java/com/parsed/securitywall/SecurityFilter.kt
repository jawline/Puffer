package com.parsed.securitywall

import android.os.Build
import android.os.Handler
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.annotation.RequiresApi
import java.io.FileOutputStream

class SecurityFilter(service: SecurityService, blockList: String): Runnable{
    val blockList = blockList;
    public var blockedTrackers = 0;

    companion object {
        const val TAG = "sec_filter"
        init {
            System.loadLibrary("security_wall")
        }
    }

    val mService = service;
    var quit: FileOutputStream? = null;

    external fun launch(fd: Int, quit_fd: Int, blockList: String)

    public fun protect(fd: Int) {
        mService.protect(fd);
    }

    public fun report(tcp: Int, total_tcp: Int, udp: Int, total_udp: Int, blocked: Int) {
        blockedTrackers = blocked

        Log.d(TAG, "Reported: " + blocked);
        mService.updateForegroundNotification(tcp + udp, total_tcp + total_udp, blockedTrackers)
    }

    @Override
    fun interrupt() {
        if (this.quit != null) {
            this.quit?.write(1);
            this.quit?.flush();
        }
    }

    @RequiresApi(Build.VERSION_CODES.LOLLIPOP)
    override fun run() {
        val vpnBuilder = mService.Builder();

        Log.i(TAG,"Starting SecurityFilter")

        vpnBuilder.addAddress("10.0.0.2", 24)
        vpnBuilder.addRoute("0.0.0.0", 0)
        vpnBuilder.setMtu(1500)

        Log.d(TAG, "Configured Builder")

        val interfaceFileDescriptor: ParcelFileDescriptor?;

        synchronized (mService) {
            interfaceFileDescriptor = vpnBuilder.establish()
        }

        Log.d(TAG,"Estabished")

        val tunFd = interfaceFileDescriptor!!.fd
        val quitPipe = ParcelFileDescriptor.createPipe()

        quit = FileOutputStream(quitPipe[1].fileDescriptor)

        Log.d(TAG, "Entering native portion");
        launch(tunFd, quitPipe[0].fd, blockList)

        interfaceFileDescriptor.close()
        quitPipe[0].close()
        quitPipe[1].close()

        Log.d(TAG, "Closing file descriptors because interrupted");
    }
}