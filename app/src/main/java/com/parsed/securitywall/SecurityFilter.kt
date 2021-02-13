package com.parsed.securitywall

import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.OsConstants.AF_INET
import android.util.Log
import androidx.annotation.RequiresApi
import java.io.FileOutputStream

class SecurityFilter(service: SecurityService, blockList: String): Thread() {
    val blockList = blockList
    var currentTcp = 0L
    var currentUdp = 0L
    var lastTcp = 0L
    var lastUdp = 0L
    var lastBlocked = 0L
    var lastBytesIn = 0L
    var lastBytesOut = 0L

    val mService = service
    var quit: FileOutputStream? = null

    external fun launch(fd: Int, quit_fd: Int, blockList: String)

    fun protect(fd: Int) {
        Log.d(TAG, "Protected socket: $fd")
        synchronized (mService) {
            if (!mService.protect(fd)) {
                Log.d(TAG, "Could not protect $fd")
            }
        }
    }

    fun report(tcp: Long, totalTcp: Long, udp: Long, totalUdp: Long, totalBytesIn: Long, totalBytesOut: Long, blocked: Long) {
        currentTcp = tcp
        currentUdp = udp
        mService.report(totalTcp - lastTcp, totalUdp - lastUdp, totalBytesIn - lastBytesIn, totalBytesOut - lastBytesOut, blocked - lastBlocked)
        lastTcp = totalTcp
        lastUdp = totalUdp
        lastBlocked = blocked
        lastBytesIn = totalBytesIn
        lastBytesOut = totalBytesOut
    }

    override fun interrupt() {
        super.interrupt()
        if (this.quit != null) {
            this.quit?.write(1)
            this.quit?.flush()
        }
    }

    @RequiresApi(Build.VERSION_CODES.LOLLIPOP)
    override fun run() {
        val vpnBuilder = mService.Builder()

        Log.i(TAG,"Starting SecurityFilter")

        vpnBuilder.allowFamily(AF_INET);
        vpnBuilder.addDnsServer("1.1.1.1");
        vpnBuilder.addDisallowedApplication("com.parsed.securitywall")
        vpnBuilder.addAddress("10.142.69.35", 32)
        vpnBuilder.addRoute("0.0.0.0", 0)
        vpnBuilder.setMtu(1500)

        Log.d(TAG, "Configured Builder")

        val interfaceFileDescriptor: ParcelFileDescriptor?

        synchronized (mService) {
            interfaceFileDescriptor = vpnBuilder.establish()
        }

        Log.d(TAG,"Estabished")

        val tunFd = interfaceFileDescriptor!!.fd
        val quitPipe = ParcelFileDescriptor.createPipe()

        quit = FileOutputStream(quitPipe[1].fileDescriptor)

        Log.d(TAG, "Entering native portion")
        launch(tunFd, quitPipe[0].fd, blockList)

        interfaceFileDescriptor.close()
        quitPipe[0].close()
        quitPipe[1].close()

        Log.d(TAG, "Closing file descriptors because interrupted")
    }

    companion object {
        const val TAG = "sec_filter"
        init {
            System.loadLibrary("security_wall")
        }
    }
}