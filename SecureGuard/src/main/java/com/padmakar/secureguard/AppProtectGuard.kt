package com.padmakar.secureguard

import android.os.Build
import android.provider.Settings
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import java.io.File
import android.os.Debug
import android.util.Log
import java.io.BufferedReader
import java.io.InputStreamReader

object AppProtectGuard {

    private fun checkRootMethod1(): Boolean {
        val buildTags = Build.TAGS
        return buildTags != null && buildTags.contains("test-keys")
    }

    private fun checkRootMethod2(): Boolean {
        val paths = arrayOf(
            "/sbin/su", "/system/bin/su", "/system/xbin/su",
            "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su",
            "/system/bin/failsafe/su", "/data/local/su", "/su/bin/su"
        )
        return paths.any { File(it).canExecute() }
    }

    private fun checkRootMethod3(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("/system/xbin/which", "su"))
            process.inputStream.bufferedReader().readLine() != null
        } catch (e: Exception) {
            false
        }
    }

    private fun isEmulator(): Boolean {
        return (Build.FINGERPRINT.lowercase().contains("generic") ||
                Build.FINGERPRINT.lowercase().contains("unknown") ||
                Build.MODEL.lowercase().contains("sdk") ||
                Build.MODEL.lowercase().contains("emulator") ||
                Build.BRAND.lowercase().contains("generic") ||
                Build.MANUFACTURER.lowercase().contains("genymotion") ||
                Build.HARDWARE.lowercase().contains("goldfish") ||
                Build.HARDWARE.lowercase().contains("ranchu") ||
                Build.PRODUCT.lowercase().contains("sdk_google") ||
                Build.PRODUCT.lowercase().contains("sdk") ||
                Build.PRODUCT.lowercase().contains("vbox86p"))
    }

    private fun isDeveloperOptionsWithUSBDebuggingEnabled(context: Context): Boolean {
        return Settings.Secure.getInt(context.contentResolver, Settings.Secure.ADB_ENABLED, 0) == 1
    }

    private fun isFridaInjected(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec("pgrep -f frida")
            process.inputStream.bufferedReader().readLine() != null
        } catch (e: Exception) {
            false
        }
    }

    private fun isDebuggerAttached(): Boolean {
        return Debug.isDebuggerConnected() || Debug.waitingForDebugger() ||
                System.getProperty("ro.debuggable") == "1"
    }

    private fun isVpnConnected(context: Context): Boolean {
        val connectivityManager =
            context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val networks: Array<Network> = connectivityManager.allNetworks

        networks.forEach { network ->
            val capabilities = connectivityManager.getNetworkCapabilities(network)
            if (capabilities != null && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                return true // VPN is active
            }
        }
        return false
    }

    private fun isProxyDetected(context: Context): Boolean {
        return try {
            val proxyAddress = System.getProperty("http.proxyHost") ?: ""
            val proxyPort = System.getProperty("http.proxyPort") ?: ""
            proxyAddress.isNotEmpty() && proxyPort.isNotEmpty()
        } catch (e: Exception) {
            false
        }
    }
    private fun isDeveloperOptionsEnabled(context: Context): Boolean {
        return Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
    }

    fun isDeviceRootedOrEmulator(context: Context): Boolean {
        return checkRootMethod1() || checkRootMethod2() || checkRootMethod3() ||
                isDeveloperOptionsEnabled(context) || isEmulator() ||
                isFridaInjected() || isDebuggerAttached() || isVpnConnected(context) ||
                isProxyDetected(context) || isDeveloperOptionsWithUSBDebuggingEnabled(context)
    }
}

