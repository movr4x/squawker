package org.ca.squawker

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ResolveInfo
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.annotation.RequiresApi
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.security.KeyStore
import java.security.cert.X509Certificate
import android.util.Base64
import android.app.NotificationManager
import android.app.NotificationChannel
import android.content.Context
import androidx.core.app.NotificationCompat

class MainActivity: FlutterActivity() {

    private val CHANNEL = "squawker/android_info"
    private val NOTIFICATION_CHANNEL_ID = "cert_debug_channel"
    private lateinit var notificationManager: NotificationManager

    private val MY_PERMISSIONS_POST_NOTIFICATIONS = 1

    private val textActivityList = ArrayList<ResolveInfo>()
    private val callbackMap = HashMap<Int, MethodChannel.Result>()

    private var methodChannel: MethodChannel? = null

    override fun onPause() {
        super.onPause()
        try {
            Thread.sleep(200)
        } catch (e: InterruptedException) {
            e.printStackTrace()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return

        val intent = Intent().setAction(Intent.ACTION_PROCESS_TEXT).setType("text/plain")
        val lst = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.queryIntentActivities(intent, PackageManager.ResolveInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            packageManager.queryIntentActivities(intent, 0)
        }
        for (item in lst) {
            textActivityList.add(item)
        }
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        setupNotificationChannel()
        notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        methodChannel = MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            CHANNEL
        )
        methodChannel!!.setMethodCallHandler { call, result ->
            when (call.method) {
                "supportedTextActivityList" -> result.success(getTextActivityList())
                "processTextActivity" -> {
                    val callbackCode = result.hashCode()
                    callbackMap[callbackCode] = result
                    processTextActivity(
                        call.argument("value") ?: "",
                        call.argument("id") ?: -1,
                        call.argument("readonly") ?: true,
                        callbackCode
                    )
                }
                "requestPostNotificationsPermissions" -> {
                    requestPostNotificationsPermissions()
                    result.success(true)
                }
                "getUserCerts" -> result.success(getUserCerts())
                else -> result.notImplemented()
            }
        }
    }

    private fun setupNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "Certificate Debug",
                NotificationManager.IMPORTANCE_LOW
            )
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun showNotification(message: String, id: Int) {
        val builder = NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_info) // Use a default icon
            .setContentTitle("Certificate Debug")
            .setContentText(message)
            .setPriority(NotificationCompat.PRIORITY_LOW)
        notificationManager.notify(id, builder.build())
    }

    private fun getUserCerts(): List<String> {
        showNotification("Starting getUserCertificates", 1)
        
        val userCerts = mutableListOf<String>()
        showNotification("After mutableListOf<String>()", 2)
        
        // Step 1: Get KeyStore instance
        val keyStore: KeyStore? = try {
            showNotification("Getting KeyStore instance", 3)
            KeyStore.getInstance("AndroidCAStore")
        } catch (e: Exception) {
            showNotification("KeyStore.getInstance failed: ${e.message}", 4)
            return userCerts
        }

        // Step 2: Load KeyStore
        try {
            showNotification("Loading KeyStore", 5)
            keyStore?.load(null, null)
        } catch (e: Exception) {
            showNotification("KeyStore.load failed: ${e.message}", 56)
            return userCerts
        }

        // Step 3: Get aliases
        val aliases = try {
            showNotification("Getting aliases", 7)
            keyStore?.aliases()
        } catch (e: Exception) {
            showNotification("aliases failed: ${e.message}", 8)
            return userCerts
        } ?: run {
            showNotification("aliases is null", 9)
            return userCerts
        }

        // Step 4: Process each alias
        showNotification("Processing aliases", 10)
        var aliasCount = 0
        while (aliases.hasMoreElements()) {
            val alias = aliases.nextElement() ?: continue
            aliasCount++
            if (alias.startsWith("user:")) {
                try {
                    showNotification("Getting cert for alias: $alias", 11 + aliasCount)
                    val cert = keyStore?.getCertificate(alias) as? X509Certificate
                    if (cert != null) {
                        val pem = "-----BEGIN CERTIFICATE-----\n" +
                                Base64.encodeToString(cert.encoded, Base64.DEFAULT) +
                                "\n-----END CERTIFICATE-----"
                        userCerts.add(pem)
                        showNotification("Added cert for alias: $alias", 40 + aliasCount)
                    } else {
                        showNotification("Cert is null for alias: $alias", 60 + aliasCount)
                    }
                } catch (e: Exception) {
                    showNotification("Cert processing failed for $alias: ${e.message}", 80 + aliasCount)
                    continue
                }
            }
        }
        showNotification("Finished with ${userCerts.size} certs", 90)
        return userCerts
    }

    private fun getUserCerts2(): List<String> {
        val userCerts = mutableListOf<String>()
        try {
            val keyStore = KeyStore.getInstance("AndroidCAStore")
            keyStore.load(null, null)
            val aliases = keyStore.aliases()
            while (aliases.hasMoreElements()) {
                try {
                    val alias = aliases.nextElement()
                    if (alias == null || !alias.startsWith("user:"))
                        continue
                    val cert = keyStore.getCertificate(alias)
                    if (cert !is X509Certificate)
                        continue
                    try {
                        val certPem = "-----BEGIN CERTIFICATE-----\n" +
                            Base64.encodeToString(cert.encoded, Base64.DEFAULT) +
                            "\n-----END CERTIFICATE-----"
                        userCerts.add(certPem)
                    } catch (e: Exception) {
                        // Cert issue?
                        continue
                    }
                } catch (e: Exception) {
                    // Alias issue?
                    continue
                }
            }
        } catch (e: Exception) {
            // KeyStore issue?
        }
        return userCerts
    }

    private fun getTextActivityList() = arrayListOf<String>().apply {
        for (item in textActivityList) {
            add(item.loadLabel(packageManager).toString())
        }
    }

    private fun processTextActivity(value: String, id: Int, readonly: Boolean, callbackCode: Int) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return

        val info = textActivityList.getOrNull(id) ?: return
        val intent = Intent().apply {
            setClassName(info.activityInfo.packageName, info.activityInfo.name)
            action = Intent.ACTION_PROCESS_TEXT
            putExtra(Intent.EXTRA_PROCESS_TEXT, value)
            putExtra(Intent.EXTRA_PROCESS_TEXT_READONLY, readonly)
            type = "text/plain"
        }
        startActivityForResult(intent, callbackCode)
    }

    @RequiresApi(Build.VERSION_CODES.M)
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        val result = if (resultCode == Activity.RESULT_OK) {
            data?.getStringExtra(Intent.EXTRA_PROCESS_TEXT)
        } else {
            null
        }
        returnResult(requestCode, result)
    }

    private fun returnResult(callbackCode: Int, result: String?) {
        callbackMap.remove(callbackCode)?.success(result)
    }

    private fun requestPostNotificationsPermissions() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                if (ActivityCompat.shouldShowRequestPermissionRationale(this, Manifest.permission.POST_NOTIFICATIONS)) {
                    Toast.makeText(this, "Please grant permissions to post local notifications", Toast.LENGTH_LONG).show()
                    ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), MY_PERMISSIONS_POST_NOTIFICATIONS)
                } else {
                    ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), MY_PERMISSIONS_POST_NOTIFICATIONS)
                }
            }
            else {
                this@MainActivity.runOnUiThread {
                    methodChannel!!.invokeMethod("requestPostNotificationsPermissionsCallback", true)
                }
            }
        }
        else {
            this@MainActivity.runOnUiThread {
                methodChannel!!.invokeMethod("requestPostNotificationsPermissionsCallback", true)
            }
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        when (requestCode) {
            MY_PERMISSIONS_POST_NOTIFICATIONS -> {
                var granted = false
                if (grantResults.isNotEmpty()) {
                    granted = (grantResults[0] == PackageManager.PERMISSION_GRANTED)
                }
                this@MainActivity.runOnUiThread {
                    methodChannel!!.invokeMethod("requestPostNotificationsPermissionsCallback", granted)
                }
            }
        }
    }

}
