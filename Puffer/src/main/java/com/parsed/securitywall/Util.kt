package com.parsed.securitywall

import android.content.Context
import java.io.BufferedReader
import java.io.IOException
import java.io.InputStream
import java.io.InputStreamReader

class Util {
    companion object {
        fun readRawTextFile(ctx: Context, resId: Int): String? {
            val inputStream: InputStream = ctx.resources.openRawResource(resId)
            val inputreader = InputStreamReader(inputStream)
            val buffreader = BufferedReader(inputreader)
            var line: String? = null
            val text = StringBuilder()
            try {
                while (buffreader.readLine().also({ line = it }) != null) {
                    text.append(line)
                    text.append('\n')
                }
            } catch (e: IOException) {
                return null
            }
            return text.toString()
        }
    }
}