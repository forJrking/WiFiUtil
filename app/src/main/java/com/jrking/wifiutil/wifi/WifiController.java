package com.jrking.wifiutil.wifi;

import android.content.ContentResolver;
import android.content.Context;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.net.wifi.WifiManager.WifiLock;
import android.os.Build;
import android.util.Log;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public class WifiController {

    private static String TAG = "WifiController";

    private static WifiManager mWifiManager;

    private static WifiInfo mWifiInfo;

    private static Context mContext;

    private List<ScanResult> mWifiList;

    private List<WifiConfiguration> mWifiConfigurations;

    private WifiLock mWifiLock;

    // 认证方式
    public static final int TYPE_NO_PASSWD = 0x11;

    public static final int TYPE_WEP = 0x12;

    public static final int TYPE_WPA = 0x13;

    // 加密方式
    public static final int ENCRYPT_TYPE_CCMP = 1;

    public static final int ENCRYPT_TYPE_TKIP = 2;

    public static final int ENCRYPT_TYPE_CCMP_TKIP = 3;


    public WifiController(Context context) {
        mContext =context;
        mWifiManager = (WifiManager)context.getSystemService(Context.WIFI_SERVICE);
        mWifiInfo = mWifiManager.getConnectionInfo();
    }

    /**
     * 打开Wifi
     */
    public void openWifi() {
        if (!mWifiManager.isWifiEnabled()) {
            mWifiManager.setWifiEnabled(true);
        }
    }

    /**
     * @return Wifi管理器
     */
    public WifiManager getWifiManager() {
        return mWifiManager;
    }


    /**
     * 是否打开Wifi
     */
    public boolean isWifiOpen() {
        return mWifiManager.isWifiEnabled();
    }

    /**
     * 关闭Wifi
     */
    public void closeWifi() {
        if (mWifiManager.isWifiEnabled()) {
            mWifiManager.setWifiEnabled(false);
        }
    }

    /**
     * Wifi状态
     */
    public int checkState() {
        return mWifiManager.getWifiState();
    }

    /**
     * Wifi
     */
    public void acquireWifiLock() {
        mWifiLock.acquire();
    }

    /**
     * Wifi锁
     */
    public void releaseWifiLock() {
        if (mWifiLock.isHeld()) {
            mWifiLock.acquire();
        }
    }

    public void createWifiLock() {
        mWifiLock = mWifiManager.createWifiLock("test");
    }

    public List<WifiConfiguration> getConfiguration() {
        return mWifiConfigurations;
    }

    public void connetionConfiguration(int index) {
        if (index > mWifiConfigurations.size()) {
            return;
        }
        mWifiManager.enableNetwork(mWifiConfigurations.get(index).networkId, true);
    }

    public void connetionNetwork(int netId) {
        if (null == mWifiConfigurations || mWifiConfigurations.size() == 0) {
            return;
        } else {
            for (WifiConfiguration config : mWifiConfigurations) {
                if (config.networkId == netId) {
                    Log.i(TAG, "connetionNetwork->" + netId);
                    mWifiManager.enableNetwork(netId, true);
                }
            }
        }

    }

    public void startScan() {
        mWifiManager.startScan();
    }

    public List<ScanResult> getWifiList() {
        mWifiList = mWifiManager.getScanResults();

        if (mWifiList != null) {
            sort(mWifiList);
        }

        mWifiConfigurations = mWifiManager.getConfiguredNetworks();

        return mWifiList;
    }

    private void sort(List<ScanResult> list) {
        Collections.sort(list, new Comparator<ScanResult>() {

            @Override
            public int compare(ScanResult arg0, ScanResult arg1) {
                // TODO Auto-generated method stub
                return arg1.level - arg0.level;
            }

        });
    }



    public StringBuffer lookUpScan() {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < mWifiList.size(); i++) {
            sb.append("Index_" + new Integer(i + 1).toString() + ":");
            sb.append((mWifiList.get(i)).toString()).append("\n");
        }
        return sb;
    }

    public String getMacAddress() {
        return (mWifiInfo == null) ? "NULL" : mWifiInfo.getMacAddress();
    }

    public String getBSSID() {
        return (mWifiInfo == null) ? "NULL" : mWifiInfo.getBSSID();
    }

    public int getIpAddress() {
        return (mWifiInfo == null) ? 0 : mWifiInfo.getIpAddress();
    }

    public int getNetWordId() {
        return (mWifiInfo == null) ? 0 : mWifiInfo.getNetworkId();
    }

    public WifiInfo getWifiInfo() {
        return mWifiInfo = mWifiManager.getConnectionInfo();
    }

    public int addNetWorkHasConfiged(WifiConfiguration configuration) {
        mWifiManager.enableNetwork(configuration.networkId, true);
        return configuration.networkId;
    }

    public int addNetWork(WifiConfiguration configuration) {
        int netId = mWifiManager.addNetwork(configuration);
        Log.i(TAG, "addNetWork:" + netId);
        mWifiManager.enableNetwork(netId, true);
        mWifiManager.updateNetwork(configuration);
        mWifiManager.reassociate();
        mWifiManager.reconnect();
        return netId;
    }

    public void disConnectionWifi(int netId) {
        // mWifiManager.disableNetwork(netId);
        mWifiManager.disconnect();
    }

    public void removeWifi(int netId) {
        // mWifiManager.removeNetwork(netId);
    }

    public int calculateSignalLevel(int rssi) {
        return mWifiManager.calculateSignalLevel(rssi, 100);
    }

    public String getServerIpAddr() {
        int serverIp = mWifiManager.getDhcpInfo().serverAddress;
        return longToIP(serverIp);
    }

    public static String longToIP(long longIp) {
        StringBuffer sb = new StringBuffer("");

        sb.append(String.valueOf((longIp & 0x000000FF)));
        sb.append(".");
        sb.append(String.valueOf((longIp & 0x0000FFFF) >>> 8));
        sb.append(".");
        sb.append(String.valueOf((longIp & 0x00FFFFFF) >>> 16));
        sb.append(".");
        sb.append(String.valueOf((longIp >>> 24)));
        // 直接右移24位
        return sb.toString();
    }

    public static int getSecurity(ScanResult result) {
        if (result.capabilities.contains("WEP")) {
            return 1;
        } else if (result.capabilities.contains("PSK")) {
            return 2;
        } else if (result.capabilities.contains("EAP")) {
            return 3;
        }
        return 0;
    }

    public WifiConfiguration createWifiInfo(String SSID, String password, int type, int encryptType) {
        Log.i(TAG,"create wifi configuration");
        Log.v(TAG, "SSID = " + SSID + "## Password = " + password + "## Type = " + type);
        WifiConfiguration config = new WifiConfiguration();
        config.allowedAuthAlgorithms.clear();
        config.allowedGroupCiphers.clear();
        config.allowedKeyManagement.clear();
        config.allowedPairwiseCiphers.clear();
        config.allowedProtocols.clear();
        if (Build.VERSION.SDK_INT >= 21)
            config.SSID = "" + SSID + "";
        else
            config.SSID = "\"" + SSID + "\"";

        WifiConfiguration tempConfig = this.IsExsits(SSID);
        if (tempConfig != null) {
            mWifiManager.removeNetwork(tempConfig.networkId);
        }

        // 分为三种情况：1没有密码2用wep加密3用wpa加密
        if (type == TYPE_NO_PASSWD) {// WIFICIPHER_NOPASS
            // config.allowedAuthAlgorithms
            // .set(WifiConfiguration.AuthAlgorithm.OPEN);
            // config.allowedAuthAlgorithms
            // .set(WifiConfiguration.AuthAlgorithm.SHARED);
            config.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE);

        } else if (type == TYPE_WEP) { // WIFICIPHER_WEP
            Log.v(TAG, "TYPE_WEP:password=" + password);

            int length = password.length();
            // WEP-40, WEP-104, and 256-bit WEP
            // (WEP-232?)
            if ((length == 10 || length == 26 || length == 58) && password.matches("[0-9A-Fa-f]*")) {
                config.wepKeys[0] = password;
            } else {
                config.wepKeys[0] = '"' + password + '"';
            }
            config.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE);
            config.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.OPEN);
            config.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.SHARED);

        } else if (type == TYPE_WPA) { // WIFICIPHER_WPA
            config.preSharedKey = "\"" + password + "\"";

            config.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.OPEN);
            config.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_PSK);

            if (encryptType == ENCRYPT_TYPE_CCMP) {
                Log.v(TAG, "TYPE_WPA,ENCRYPT_TYPE_CCMP");
                config.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
                config.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);
            } else if (encryptType == ENCRYPT_TYPE_TKIP) {
                Log.v(TAG, "TYPE_WPA,ENCRYPT_TYPE_TKIP");
                config.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);
                config.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.TKIP);
            } else if (encryptType == ENCRYPT_TYPE_CCMP_TKIP) {
                Log.v(TAG, "TYPE_WPA,ENCRYPT_TYPE_CCMP_TKIP");
                config.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);
                config.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.TKIP);
                config.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
                config.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);
            }
            config.status = WifiConfiguration.Status.ENABLED;

        }

        return config;
    }

    private WifiConfiguration IsExsits(String SSID) {
        List<WifiConfiguration> existingConfigs = mWifiManager.getConfiguredNetworks();
        if (existingConfigs == null) {
            return null;
        }
        for (WifiConfiguration existingConfig : existingConfigs) {
            if (existingConfig.SSID.equals("\"" + SSID + "\"")) {
                return existingConfig;
            }
        }
        return null;
    }

    // ========================================================================================================

    /**
     * 通过设置静态IP的方式切换到指定wifi
     */
    public int switchToDevWifi(final String devWifiSSID, String pwd, String ip, int networkPrefixLength)
            throws Exception {
        WifiConfiguration wifiConfig = createWifiInfo(devWifiSSID, pwd, TYPE_WPA, ENCRYPT_TYPE_CCMP); // 设备AP的认证类型为WAP,加密类型为CCMP
        InetAddress intetAddress = InetAddress.getByName(ip);
        int intIp = inetAddressToInt(intetAddress);
        String dns = (intIp & 0xFF) + "." + ((intIp >> 8) & 0xFF) + "." + ((intIp >> 16) & 0xFF) + ".1";
        int netId;
        boolean hasField = hasField(wifiConfig, "ipAssignment");
////        boolean hasField = hasField(wifiConfig, "mIpConfiguration");

        if (Build.VERSION.SDK_INT > 11) {
            if (hasField) {
                setIpAssignment("STATIC", wifiConfig);
                setIpAddress(intetAddress, networkPrefixLength, wifiConfig);
                setGateway(InetAddress.getByName(dns), wifiConfig);
                setDNS(InetAddress.getByName(dns), wifiConfig);

                netId = mWifiManager.addNetwork(wifiConfig);
                mWifiManager.enableNetwork(netId, true);
                mWifiManager.updateNetwork(wifiConfig);
            } else {
                setStaticIpAssignment(wifiConfig, intetAddress, InetAddress.getByName(dns), networkPrefixLength);
                wifiManagerConnect(wifiConfig);
                netId = -1;
            }

        } else {
            netId = mWifiManager.addNetwork(wifiConfig);
            mWifiManager.enableNetwork(netId, true);
            mWifiManager.updateNetwork(wifiConfig);

            ContentResolver ctRes = mContext.getContentResolver();
            android.provider.Settings.System.putInt(ctRes, android.provider.Settings.System.WIFI_USE_STATIC_IP, 1);
            android.provider.Settings.System.putString(ctRes, android.provider.Settings.System.WIFI_STATIC_IP, ip);
            android.provider.Settings.System.putString(ctRes, android.provider.Settings.System.WIFI_STATIC_NETMASK,
                    "255.255.255.0");
            android.provider.Settings.System.putString(ctRes, android.provider.Settings.System.WIFI_STATIC_GATEWAY,
                    "192.168.58.1");
            android.provider.Settings.System.putString(ctRes, android.provider.Settings.System.WIFI_STATIC_DNS1,
                    "192.168.58.1");
        }

        return netId;
    }

    public void switchToUserWifi(String ssid, String password, int type, int encryptType) throws Exception {
        WifiConfiguration config = createWifiInfo(ssid, password, type, encryptType);
        boolean hasField = hasField(config, "ipAssignment");
        if (Build.VERSION.SDK_INT > 11) {
            if (hasField) {
                setIpAssignment("DHCP", config);
                int netId = mWifiManager.addNetwork(config);
                mWifiManager.enableNetwork(netId, true);
                mWifiManager.updateNetwork(config);
            } else {
                setDhcpIpAssignment(config);
                wifiManagerConnect(config);
            }
        } else {
            ContentResolver ctRes = mContext.getContentResolver();
            android.provider.Settings.System.putInt(ctRes, android.provider.Settings.System.WIFI_USE_STATIC_IP, 0);
            int netId = mWifiManager.addNetwork(config);
            mWifiManager.enableNetwork(netId, true);
            mWifiManager.updateNetwork(config);
        }

    }

    /***
     * Convert a IPv4 address from an InetAddress to an integer
     *
     * @param inetAddr is an InetAddress corresponding to the IPv4 address
     * @return the IP address as an integer in network byte order
     */
    public static int inetAddressToInt(InetAddress inetAddr) throws IllegalArgumentException {
        byte[] addr = inetAddr.getAddress();
        if (addr.length != 4) {
            throw new IllegalArgumentException("Not an IPv4 address");
        }
        return ((addr[3] & 0xff) << 24) | ((addr[2] & 0xff) << 16) | ((addr[1] & 0xff) << 8) | (addr[0] & 0xff);
    }

    /**
     * 查找已经设置好的Wifi
     *
     * @param ssid
     * @return
     */
    public WifiConfiguration getHistoryWifiConfig(String ssid) {
        List<WifiConfiguration> localList = mWifiManager.getConfiguredNetworks();
        for (WifiConfiguration wc : localList) {
            if (("\"" + ssid + "\"").equals(wc.SSID)) {
                return wc;
            }
            mWifiManager.disableNetwork(wc.networkId);
        }
        return null;
    }

    public static void setIpAssignment(String assign, WifiConfiguration wifiConf) throws Exception {
        setEnumField(wifiConf, assign, "ipAssignment");
    }

    public void setDhcpIpAssignment(WifiConfiguration wifiConf) throws ClassNotFoundException, NoSuchMethodException,
            IllegalAccessException, IllegalArgumentException, InvocationTargetException, InstantiationException {

        Class cls = wifiConf.getClass();
        Class ipAssignmentClass = Class.forName("android.net.IpConfiguration$IpAssignment");
        Class proxySettingClass = Class.forName("android.net.IpConfiguration$ProxySettings");
        Class staticConfigurationClass = Class.forName("android.net.StaticIpConfiguration");
        Class httpProxyClass = Class.forName("android.net.ProxyInfo");
        Class linkAddressClass = Class.forName("android.net.LinkAddress");

        Class ipConfig = Class.forName("android.net.IpConfiguration");
        Constructor ipConfigurationConstructor = ipConfig.getConstructor(ipAssignmentClass, proxySettingClass,
                staticConfigurationClass, httpProxyClass);

        Enum ipEnum = Enum.valueOf(ipAssignmentClass, "DHCP");
        Enum proxyEnum = Enum.valueOf(proxySettingClass, "NONE");

        Object ipConfiguration = ipConfigurationConstructor.newInstance(ipEnum, proxyEnum, null, null);
        Method method = cls.getDeclaredMethod("setIpConfiguration", ipConfig);
        method.invoke(wifiConf, ipConfiguration);
        Log.i(TAG,"set ip assignment");

    }

    void setStaticIpAssignment(WifiConfiguration wifiConf, InetAddress address, InetAddress gatway, int prefix)
            throws ClassNotFoundException, NoSuchMethodException, IllegalAccessException, IllegalArgumentException,
            InvocationTargetException, InstantiationException, SecurityException, NoSuchFieldException {

        Class cls = wifiConf.getClass();
        Class ipAssignmentClass = Class.forName("android.net.IpConfiguration$IpAssignment");
        Class proxySettingClass = Class.forName("android.net.IpConfiguration$ProxySettings");
        Class staticConfigurationClass = Class.forName("android.net.StaticIpConfiguration");
        Class httpProxyClass = Class.forName("android.net.ProxyInfo");
        Class linkAddressClass = Class.forName("android.net.LinkAddress");

        Class ipConfig = Class.forName("android.net.IpConfiguration");
        Constructor ipConfigurationConstructor = ipConfig.getConstructor(ipAssignmentClass, proxySettingClass,
                staticConfigurationClass, httpProxyClass);

        Enum ipEnum = Enum.valueOf(ipAssignmentClass, "STATIC");
        Enum proxyEnum = Enum.valueOf(proxySettingClass, "NONE");
        //会报异常 为 java.lang.IllegalArgumentException: Wrong number of arguments
        Object staticConfiguration = staticConfigurationClass.getConstructor(new Class[0]).newInstance(new Object[0]);
//        Object staticConfiguration = staticConfigurationClass.getConstructor(null).newInstance(null);
        Object linkAddressInstance = linkAddressClass.getConstructor(InetAddress.class, int.class).newInstance(address,
                prefix);
        ArrayList<InetAddress> dnsList = new ArrayList<InetAddress>();
        dnsList.add(gatway);

        setField(staticConfiguration, dnsList, "dnsServers");
        setField(staticConfiguration, linkAddressInstance, "ipAddress");
        setField(staticConfiguration, gatway, "gateway");

        Object ipConfiguration = ipConfigurationConstructor.newInstance(ipEnum, proxyEnum, staticConfiguration, null);
        Method method = cls.getDeclaredMethod("setIpConfiguration", ipConfig);
        method.invoke(wifiConf, ipConfiguration);

    }

    public static void setIpAddress(InetAddress addr, int prefixLength, WifiConfiguration wifiConf)
            throws SecurityException, IllegalArgumentException, NoSuchFieldException, IllegalAccessException,
            NoSuchMethodException, ClassNotFoundException, InstantiationException, InvocationTargetException {
        Object linkProperties = getField(wifiConf, "linkProperties");
        if (linkProperties == null)
            return;
        Class laClass = Class.forName("android.net.LinkAddress");
        Constructor laConstructor = laClass.getConstructor(new Class[]{InetAddress.class, int.class});
        Object linkAddress = laConstructor.newInstance(addr, prefixLength);
        ArrayList mLinkAddresses = (ArrayList) getDeclaredField(linkProperties, "mLinkAddresses");
        mLinkAddresses.clear();
        mLinkAddresses.add(linkAddress);
    }

    public static void setGateway(InetAddress gateway, WifiConfiguration wifiConf) throws SecurityException,
            IllegalArgumentException, NoSuchFieldException, IllegalAccessException, ClassNotFoundException,
            NoSuchMethodException, InstantiationException, InvocationTargetException {
        Object linkProperties = getField(wifiConf, "linkProperties");
        if (linkProperties == null)
            return;
        Class routeInfoClass = Class.forName("android.net.RouteInfo");
        Constructor routeInfoConstructor = routeInfoClass.getConstructor(new Class[]{InetAddress.class});
        Object routeInfo = routeInfoConstructor.newInstance(gateway);
        ArrayList mRoutes = (ArrayList) getDeclaredField(linkProperties, "mRoutes");
        mRoutes.clear();
        mRoutes.add(routeInfo);
    }

    public static void setDNS(InetAddress dns, WifiConfiguration wifiConf) throws SecurityException,
            IllegalArgumentException, NoSuchFieldException, IllegalAccessException {
        Object linkProperties = getField(wifiConf, "linkProperties");
        if (linkProperties == null)
            return;
        ArrayList<InetAddress> mDnses = (ArrayList<InetAddress>) getDeclaredField(linkProperties, "mDnses");
        mDnses.clear(); // or add a new dns address , here I just want to
        // replace DNS1
        mDnses.add(dns);
    }

    public static String getNetworkPrefixLength(WifiConfiguration wifiConf) {
        String address = "";
        try {
            Object linkProperties = getField(wifiConf, "linkProperties");
            if (linkProperties == null)
                return null;

            if (linkProperties != null) {
                ArrayList mLinkAddresses = (ArrayList) getDeclaredField(linkProperties, "mLinkAddresses");
                if (mLinkAddresses != null && mLinkAddresses.size() > 0) {
                    Object linkAddressObj = mLinkAddresses.get(0);
                    address = linkAddressObj.getClass().getMethod("getNetworkPrefixLength", new Class[]{})
                            .invoke(linkAddressObj, new Object())
                            + "";
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return address;
    }

    public static InetAddress getIpAddress(WifiConfiguration wifiConf) {
        InetAddress address = null;
        try {
            Object linkProperties = getField(wifiConf, "linkProperties");
            if (linkProperties == null)
                return null;

            if (linkProperties != null) {
                ArrayList mLinkAddresses = (ArrayList) getDeclaredField(linkProperties, "mLinkAddresses");
                if (mLinkAddresses != null && mLinkAddresses.size() > 0) {
                    Object linkAddressObj = mLinkAddresses.get(0);
                    address = (InetAddress) linkAddressObj.getClass().getMethod("getAddress", new Class[]{})
                            .invoke(linkAddressObj, new Object());
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return address;
    }

    public static InetAddress getGateway(WifiConfiguration wifiConf) {
        InetAddress address = null;
        try {
            Object linkProperties = getField(wifiConf, "linkProperties");

            if (linkProperties != null) {
                ArrayList mRoutes = (ArrayList) getDeclaredField(linkProperties, "mRoutes");
                if (mRoutes != null && mRoutes.size() > 0) {
                    Object linkAddressObj = mRoutes.get(0);
                    address = (InetAddress) linkAddressObj.getClass().getMethod("getGateway", new Class[]{})
                            .invoke(linkAddressObj, new Object());
                }
            }
        } catch (Exception e) {
            Log.i(TAG, "getGateway->" + e.getMessage());
        }
        return address;
    }

    public static InetAddress getDNS(WifiConfiguration wifiConf) {
        InetAddress address = null;
        try {
            Object linkProperties = getField(wifiConf, "linkProperties");

            if (linkProperties != null) {
                ArrayList<InetAddress> mDnses = (ArrayList<InetAddress>) getDeclaredField(linkProperties, "mDnses");
                if (mDnses != null && mDnses.size() > 0) {
                    address = (InetAddress) mDnses.get(0);
                }
            }
        } catch (Exception e) {
            Log.i(TAG, "getDNS->" + e.getMessage());
        }

        return address;
    }

    public static Object getField(Object obj, String name) throws SecurityException, NoSuchFieldException,
            IllegalArgumentException, IllegalAccessException {
        Field f = obj.getClass().getField(name);
        Object out = f.get(obj);
        return out;
    }

    boolean hasField(Object obj, String name) {
        try {
            Field f = obj.getClass().getDeclaredField(name);
        } catch (NoSuchFieldException e) {
            return false;
        }
        return true;
    }

    void wifiManagerConnect(WifiConfiguration wc) throws NoSuchMethodException, ClassNotFoundException,
            IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        Class cls = mWifiManager.getClass();
        Method method = cls.getDeclaredMethod("connect", WifiConfiguration.class,
                Class.forName("android.net.wifi.WifiManager$ActionListener"));
        method.invoke(mWifiManager, wc, null);
    }

    public static Object getDeclaredField(Object obj, String name) throws SecurityException, NoSuchFieldException,
            IllegalArgumentException, IllegalAccessException {
        Field f = obj.getClass().getDeclaredField(name);
        f.setAccessible(true);
        Object out = f.get(obj);
        return out;
    }

    void setField(Object obj, Object value, String fieldName) throws NoSuchFieldException, IllegalAccessException,
            IllegalArgumentException {
        Class cls = obj.getClass();
        Field field = cls.getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static void setEnumField(Object obj, String value, String name) throws Exception {
        //setIpAssignment
        Field f = obj.getClass().getField(name);
        f.set(obj, Enum.valueOf((Class<Enum>) f.getType(), value));
//        Method method = obj.getClass().getMethod("setIpAssignment",Class.forName("android.net.IpConfiguration"))
    }

}
