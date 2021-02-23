package com.parsed.securitywall

import android.content.Context
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.ImageButton
import android.widget.LinearLayout
import android.widget.Switch
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.io.*

class BlockListActivity: AppCompatActivity() {

    class BlockList(path: String, context: Context) {
        val file = File(context.dataDir.absolutePath + path)
        var list = ArrayList<Pair<Int, String>>()
        var currentId = 0

        fun addItem(website: String) {
            list.add(Pair(currentId++, website))
            save()
        }

        fun deleteItem(id: Int) {
            val found = list.find({i -> i.first == id})
            if (found != null) {
                list.remove(found)
            }
            save()
        }

        fun save() {
            try {
                val jsonStr = Gson().toJson(this)
                val f = BufferedWriter(FileWriter(file))
                f.write(jsonStr)
                f.close()
            } catch (e: IOException) {
                Log.d(SecurityStatistics.TAG, "Could not save statistics")
            }
        }

        fun load() {
            try {
                val f = InputStreamReader(FileInputStream(file))
                this.list = Gson().fromJson(f, object : TypeToken<BlockList>() {}.type)
                f.close()
            } catch (e: IOException) {
                Log.d(TAG, "Failed to load blocklist")
            }
        }

    }

    var entries = BlockList("block", this)
    var blockList: LinearLayout? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.block_list_view)
        this.dataDir
        try {
            this.supportActionBar!!.hide()
        } catch (e: NullPointerException) {}

        blockList = findViewById<LinearLayout>(R.id.block_list)
    }

    fun reloadList() {
        entries.load()
        blockList!!.removeAllViews()
        for (entry in entries.list) {
            addWebsiteItem(entry.first, entry.second)
        }
    }

    fun addWebsiteItem(id: Int, website: String) {
        val newItem = View.inflate(this, R.layout.block_list_item, null)
        newItem.findViewById<TextView>(R.id.block_website).text = website
        newItem.findViewById<ImageButton>(R.id.bEdit).setOnClickListener(View.OnClickListener {view -> {
            entries.deleteItem(id)
            // TODO: Edit modal
        }})
        newItem.findViewById<ImageButton>(R.id.bDelete).setOnClickListener(View.OnClickListener {view -> {
            entries.deleteItem(id)
            // TODO: Confirm modal
        }})
        blockList!!.addView(newItem)
    }

    companion object {
        val TAG: String = "BlockList"
    }
}