package com.parsed.securitywall

import android.util.Log
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.io.*

class SecurityStatistics {
    var totalTcp: Long
    var totalUdp: Long
    var totalBytesIn: Long
    var totalBytesOut: Long
    var trackersBlocked: Long

    init {
        totalTcp = 0
        totalUdp = 0
        totalBytesIn = 0
        totalBytesOut = 0
        trackersBlocked = 0
    }

    fun totalConnections() = totalTcp + totalUdp

    fun save(file: File) {
        try {
            val jsonStr = Gson().toJson(this)
            val f = BufferedWriter(FileWriter(file))
            f.write(jsonStr)
            f.close()
        } catch (e: IOException) {
            Log.d(TAG, "Could not save statistics")
        }
    }

    companion object {
        fun load(file: File): SecurityStatistics {
            try {
                val f = InputStreamReader(FileInputStream(file))
                val res: SecurityStatistics = Gson().fromJson(f, object: TypeToken<SecurityStatistics>(){}.type)
                f.close()
                return res
            } catch (e: IOException) {
                return SecurityStatistics()
            }
        }
        const val TAG: String = "SecurityStatistics"
    }
}