package com.parsed.securitywall

import android.app.AlertDialog
import android.content.Context
import android.content.DialogInterface
import android.os.Bundle
import android.text.InputType
import android.util.Log
import android.view.View
import android.widget.EditText
import android.widget.ImageButton
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.google.android.material.tabs.TabLayout
import com.google.android.material.tabs.TabLayout.OnTabSelectedListener
import com.google.android.material.tabs.TabLayout.Tab
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.io.*


class BlockListActivity: AppCompatActivity() {

    class BlockList(context: Context, path: String) {
        val file = File(ContextCompat.getDataDir(context)!!.absolutePath + "/" + path)

        class BlockListContent {
            var list = ArrayList<Pair<Int, String>>()
            var currentId = 0
        }

        var content = BlockListContent()

        fun addItem(website: String) {
            content.list.add(Pair(content.currentId++, website))
            save()
        }

        fun deleteItem(id: Int) {
            val found = content.list.find({ i -> i.first == id })
            if (found != null) {
                content.list.remove(found)
            }
            save()
        }

        fun asString() = content.list.joinToString(separator="\n") {
            it.second
        }

        fun save() {
            try {
                val jsonStr = Gson().toJson(this.content)
                val f = BufferedWriter(FileWriter(file))
                f.write(jsonStr)
                f.close()
            } catch (e: IOException) {
                Log.d(SecurityStatistics.TAG, "Could not save BlockList (" + file.absolutePath + ")")
            }
        }

        fun load() {
            try {
                val f = InputStreamReader(FileInputStream(file))
                this.content = Gson().fromJson(f, object : TypeToken<BlockListContent>() {}.type)
                f.close()
            } catch (e: IOException) {
                Log.d(TAG, "Failed to load blocklist. Creating a fresh one")
            }
        }
    }

    var entries: BlockList? = null
    var blockList: LinearLayout? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.block_list_view)

        try {
            this.supportActionBar!!.hide()
        } catch (e: NullPointerException) {}


        val tabs = findViewById<TabLayout>(R.id.tabLayout)
        val block = tabs.getTabAt(0)
        val allow = tabs.getTabAt(1)

        val ctx = this

        tabs.addOnTabSelectedListener(object : OnTabSelectedListener {
            override fun onTabSelected(tab: Tab) {
                if (tab == block) {
                    setBlockList(block(ctx))
                } else if (tab == allow) {
                    setBlockList(allow(ctx))
                }
            }
            override fun onTabUnselected(tab: Tab) {}
            override fun onTabReselected(tab: Tab) {}
        })

        setBlockList(block(this))
    }

    fun setBlockList(list: BlockList) {
        Log.d(TAG, "Loading " + list)
        entries = list
        blockList = findViewById<LinearLayout>(R.id.block_list)
        reloadList()
    }

    private fun reloadList() {
        blockList!!.removeAllViews()
        for (entry in entries!!.content.list) {
            addWebsiteItem(entry.first, entry.second)
        }
    }

    fun addNewItem(_view: View) {
        val builder: AlertDialog.Builder = this.let {
            AlertDialog.Builder(it)
        }

        builder.setTitle("Domain or IP address to block")

        // Add the edit text
        val input = EditText(this)
        input.inputType = InputType.TYPE_CLASS_TEXT
        builder.setView(input)

        builder.setPositiveButton("OK"
        ) { _, _ -> run {
            entries!!.addItem(input.text.toString())
            reloadList()
        }}
        builder.setNegativeButton("Cancel"
        ) { dialog, _ -> dialog.cancel() }

        val dialog: AlertDialog? = builder.create()
        dialog!!.show()
    }

    private fun editItem(id: Int, current: String) {

        val builder: AlertDialog.Builder? = this.let {
            AlertDialog.Builder(it)
        }

        builder!!.setTitle("Domain or IP address to block")

        // Add the edit text
        val input = EditText(this)
        input.inputType = InputType.TYPE_CLASS_TEXT
        input.setText(current)
        builder.setView(input)

        builder.setPositiveButton("OK",
            DialogInterface.OnClickListener { _, _ -> run {
                entries!!.deleteItem(id)
                entries!!.addItem(input.text.toString())
                reloadList()
            }})
        builder.setNegativeButton("Cancel",
            DialogInterface.OnClickListener { dialog, _ -> dialog.cancel() })

        val dialog: AlertDialog? = builder.create()
        dialog!!.show()
    }

    private fun addWebsiteItem(id: Int, website: String) {
        val newItem = View.inflate(this, R.layout.block_list_item, null)
        newItem.findViewById<TextView>(R.id.block_website).text = website
        newItem.findViewById<ImageButton>(R.id.bEdit).setOnClickListener { _ ->
            run {
                editItem(id, website)
            }
        }
        newItem.findViewById<ImageButton>(R.id.bDelete).setOnClickListener { _ ->
            run {
                entries!!.deleteItem(id)
                reloadList()
            }
        }
        blockList!!.addView(newItem)
    }

    companion object {
        val TAG: String = "BlockList"

        fun block(context: Context): BlockList {
            val r = BlockList(context, "block")
            r.load()
            return r
        }
        fun allow(context: Context): BlockList {
            val r = BlockList(context, "allow")
            r.load()
            return r
        }
    }
}