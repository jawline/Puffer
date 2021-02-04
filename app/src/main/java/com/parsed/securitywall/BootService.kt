package com.parsed.securitywall

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import java.io.File
import java.io.IOException

class BootService : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            Log.d(TAG, "SecurityWall starting up")
            if (bootFile(context).exists()) {
                startSecurityService(context)
            }
        }
    }

    companion object {
        private fun bootFilePath(ctx: Context): String = ctx.cacheDir.absolutePath + BOOT_FILE
        fun bootFile(ctx: Context): File = File(bootFilePath(ctx))

        fun autostartOnBoot(ctx: Context) {
            try {
                val bootFile = bootFile(ctx)
                if (bootFile.createNewFile()) {
                    Log.d(TAG, "Created boot file")
                } else {
                    Log.d(TAG, "Already set to auto start")
                }
            } catch (e: IOException) {
                e.printStackTrace()
                Log.d(TAG, "Could not enable autoboot")
            }
        }

        fun cancelOnBoot(ctx: Context) {
            val bootFile = bootFile(ctx)
            bootFile.delete()
            Log.d(TAG, "Disabled autoboot")
        }

        private fun getSecurityServiceIntent(ctx: Context): Intent = Intent(ctx, SecurityService::class.java)
        fun startSecurityService(ctx: Context) = ctx.startService(getSecurityServiceIntent(ctx).setAction(SecurityService.ACTION_START))
        fun stopSecurityService(ctx: Context) = ctx.startService(getSecurityServiceIntent(ctx).setAction(SecurityService.ACTION_STOP))

        const val TAG: String = "SecurityWall Boot Service"
        const val BOOT_FILE: String = ".boot_data"
    }
}