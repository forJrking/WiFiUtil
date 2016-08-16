package com.jrking.wifiutil;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import com.jrking.wifiutil.wifi.WifiController;

import java.util.Random;

public class MainActivity extends AppCompatActivity implements View.OnClickListener {

    private static final String SSID = "meirenji003800";
    private static final String PWD = "xiaozhou123";

    private Button open;
    private Button close;
    private Button connect_ap;
    private TextView text;
    private WifiController mWifiController;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        initView();
    }

    private void initView() {
        open = (Button) findViewById(R.id.open);
        close = (Button) findViewById(R.id.close);
        connect_ap = (Button) findViewById(R.id.connect_ap);
        text = (TextView) findViewById(R.id.text);
        mWifiController = new WifiController(this);
        open.setOnClickListener(this);
        close.setOnClickListener(this);
        connect_ap.setOnClickListener(this);
    }

    @Override
    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.open:
                mWifiController.openWifi();
                break;
            case R.id.close:
                mWifiController.closeWifi();
                break;
            case R.id.connect_ap:
                try {
                    String ip = "192.168.58." + (new Random().nextInt(254) + 2);
                    mWifiController.switchToDevWifi(SSID, PWD, ip, 24);
                } catch (Exception e) {
                    text.setText(e.getMessage());
                    e.printStackTrace();
                }
                break;
        }
    }
}
