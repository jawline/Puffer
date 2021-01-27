package com.parsed.securitywall;

import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Handler;
import android.os.Message;
import android.util.Log;

import androidx.annotation.NonNull;

public class SecurityService extends VpnService implements Handler.Callback {
    public static final String TAG = "SecurityService";
    public static final String ACTION_START = "com.parsed.securitywall.START";
    public static final String ACTION_STOP = "com.parsed.securitywall.STOP";

    private Handler mHandler;
    private PendingIntent mConfigureIntent;
    private Thread mFilterThread;

    @Override
    public void onCreate() {

        if (mHandler == null) {
            mHandler = new Handler(this);
        }

        mConfigureIntent = PendingIntent.getActivity(this, 0, new Intent(this, SecurityWall.class),
                PendingIntent.FLAG_UPDATE_CURRENT);

        Log.d(TAG, "Service Created");
    }

    void connect() {
        Log.d(TAG, "Starting SecurityFilter thread");
        mFilterThread = new Thread(new SecurityFilter(this), "SecurityFilter");
        mFilterThread.start();
    }

    void disconnect() {
        Log.d(TAG, "Stopping SecurityFilter thread");
        if (mFilterThread != null) {
            mFilterThread.interrupt();
            mFilterThread = null;
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.d(TAG, "onStart");
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            disconnect();
            return START_NOT_STICKY;
        } else {
            Log.d(TAG, "connecting");
            connect();
            return START_STICKY;
        }
    }

    @Override
    public boolean handleMessage(@NonNull Message msg) {
        return false;
    }
}
