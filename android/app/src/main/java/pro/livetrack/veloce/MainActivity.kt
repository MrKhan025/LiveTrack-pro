package pro.livetrack.veloce

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.BatteryManager
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.*
import org.json.JSONObject
import pro.livetrack.veloce.audio.ConsentAudioStreamer
import pro.livetrack.veloce.telemetry.LiveTrackForegroundService
import java.net.HttpURLConnection
import java.net.URL

class MainActivity : AppCompatActivity() {

    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    private var audioStreamer: ConsentAudioStreamer? = null
    private var isTrackingGps = false
    private var isRecordingConsentAudio = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val rootLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 64, 48, 48)
        }

        val titleView = TextView(this).apply {
            text = "LiveTrack-Pro\nUnified GPS & Consent Audio"
            textSize = 22f
        }
        val micIndicatorBanner = TextView(this).apply {
            text = "🔴 VISIBLE MICROPHONE INDICATOR: ACTIVE USER-CONSENTED RECORDING"
            setBackgroundColor(0xFFB91C1C.toInt())
            setTextColor(0xFFFFFFFF.toInt())
            setPadding(24, 24, 24, 24)
            visibility = View.GONE
        }

        val serverInput = EditText(this).apply {
            hint = "Server URL (e.g. https://livetrack.example.com)"
            setText("https://10.0.2.2:4000")
        }
        val pairingInput = EditText(this).apply {
            hint = "6-Digit Pairing Code"
        }
        val pairButton = Button(this).apply {
            text = "Pair Device with Unified Account"
        }

        val gpsToggleButton = Button(this).apply {
            text = "Start Fused Location GPS Tracking"
        }

        val consentCheckBox = CheckBox(this).apply {
            text = "I explicitly consent to initiate microphone recording & live streaming with a persistent notification."
        }
        val audioToggleButton = Button(this).apply {
            text = "Start User-Initiated Microphone Recording"
            isEnabled = false
        }

        val sosButton = Button(this).apply {
            text = "🚨 Trigger Emergency SOS Beacon"
        }
        val statusText = TextView(this).apply {
            text = "Status: Ready. No covert or remote activation is permitted."
            setPadding(0, 24, 0, 0)
        }

        consentCheckBox.setOnCheckedChangeListener { _, isChecked ->
            audioToggleButton.isEnabled = isChecked || isRecordingConsentAudio
        }

        pairButton.setOnClickListener {
            val code = pairingInput.text.toString().trim()
            val baseUrl = serverInput.text.toString().trim()
            if (code.length < 4) {
                Toast.makeText(this, "Enter valid pairing code", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            scope.launch {
                statusText.text = "Pairing device..."
                val result = pairDeviceWithBackend(baseUrl, code)
                statusText.text = result
            }
        }

        gpsToggleButton.setOnClickListener {
            if (!hasLocationPermissions()) {
                requestRuntimePermissions()
                return@setOnClickListener
            }
            val baseUrl = serverInput.text.toString().trim()
            val svcIntent = Intent(this, LiveTrackForegroundService::class.java).apply {
                putExtra("SERVER_URL", baseUrl)
                putExtra("ACTION", if (isTrackingGps) "STOP_GPS" else "START_GPS")
            }
            if (!isTrackingGps) {
                ContextCompat.startForegroundService(this, svcIntent)
                isTrackingGps = true
                gpsToggleButton.text = "Stop Fused Location GPS Tracking"
                statusText.text = "GPS Tracking Active (Persistent Foreground Notification visible)"
            } else {
                startService(svcIntent)
                isTrackingGps = false
                gpsToggleButton.text = "Start Fused Location GPS Tracking"
                statusText.text = "GPS Tracking Stopped"
            }
        }

        audioToggleButton.setOnClickListener {
            if (!hasAudioPermission()) {
                requestRuntimePermissions()
                return@setOnClickListener
            }
            val baseUrl = serverInput.text.toString().trim()
            val prefs = getSharedPreferences("livetrack_prefs", MODE_PRIVATE)
            val token = prefs.getString("device_token", null)
            val deviceId = prefs.getString("device_id", null)

            if (token == null || deviceId == null) {
                Toast.makeText(this, "Pair device before starting consent audio", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (!isRecordingConsentAudio) {
                if (!consentCheckBox.isChecked) {
                    Toast.makeText(this, "Explicit user consent is mandatory", Toast.LENGTH_SHORT).show()
                    return@setOnClickListener
                }
                micIndicatorBanner.visibility = View.VISIBLE
                audioStreamer = ConsentAudioStreamer(this, baseUrl, deviceId, token)
                audioStreamer?.startExplicitUserRecording { status ->
                    runOnUiThread { statusText.text = status }
                }
                isRecordingConsentAudio = true
                audioToggleButton.text = "Stop & Encrypt Consent Recording"
            } else {
                audioStreamer?.stopAndUploadRecording { status ->
                    runOnUiThread {
                        micIndicatorBanner.visibility = View.GONE
                        statusText.text = status
                    }
                }
                isRecordingConsentAudio = false
                audioToggleButton.text = "Start User-Initiated Microphone Recording"
            }
        }

        sosButton.setOnClickListener {
            val baseUrl = serverInput.text.toString().trim()
            scope.launch {
                statusText.text = triggerSosAlert(baseUrl)
            }
        }

        rootLayout.addView(titleView)
        rootLayout.addView(micIndicatorBanner)
        rootLayout.addView(serverInput)
        rootLayout.addView(pairingInput)
        rootLayout.addView(pairButton)
        rootLayout.addView(gpsToggleButton)
        rootLayout.addView(consentCheckBox)
        rootLayout.addView(audioToggleButton)
        rootLayout.addView(sosButton)
        rootLayout.addView(statusText)

        setContentView(rootLayout)
    }

    private suspend fun pairDeviceWithBackend(baseUrl: String, code: String): String = withContext(Dispatchers.IO) {
        try {
            val url = URL("$baseUrl/api/devices/pair")
            val conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
            }
            val payload = JSONObject().put("pairingCode", code).toString()
            conn.outputStream.use { it.write(payload.toByteArray()) }
            val responseText = conn.inputStream.bufferedReader().readText()
            val json = JSONObject(responseText)
            val token = json.getString("deviceAccessToken")
            val deviceObj = json.getJSONObject("device")
            val deviceId = deviceObj.getString("id")

            getSharedPreferences("livetrack_prefs", MODE_PRIVATE).edit()
                .putString("device_token", token)
                .putString("device_id", deviceId)
                .apply()

            "Paired Successfully: ${deviceObj.getString("deviceName")}"
        } catch (e: Exception) {
            "Pairing Failed: ${e.message}"
        }
    }

    private suspend fun triggerSosAlert(baseUrl: String): String = withContext(Dispatchers.IO) {
        try {
            val prefs = getSharedPreferences("livetrack_prefs", MODE_PRIVATE)
            val token = prefs.getString("device_token", null) ?: return@withContext "Pair device first"
            val deviceId = prefs.getString("device_id", null) ?: return@withContext "Pair device first"
            val bm = getSystemService(BATTERY_SERVICE) as BatteryManager
            val battery = bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)

            val url = URL("$baseUrl/api/sos/trigger")
            val conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
                setRequestProperty("Authorization", "Bearer $token")
            }
            val body = JSONObject()
                .put("deviceId", deviceId)
                .put("latitude", 17.3850)
                .put("longitude", 78.4867)
                .put("batteryLevel", battery)
                .put("message", "Android User-Initiated SOS Beacon")
                .toString()
            conn.outputStream.use { it.write(body.toByteArray()) }
            conn.inputStream.bufferedReader().readText()
            "🚨 Emergency SOS Beacon Dispatched!"
        } catch (e: Exception) {
            "SOS Error: ${e.message}"
        }
    }

    private fun hasLocationPermissions(): Boolean {
        return ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
    }

    private fun hasAudioPermission(): Boolean {
        return ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED
    }

    private fun requestRuntimePermissions() {
        val perms = mutableListOf(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION,
            Manifest.permission.RECORD_AUDIO
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            perms.add(Manifest.permission.POST_NOTIFICATIONS)
        }
        ActivityCompat.requestPermissions(this, perms.toTypedArray(), 1001)
    }

    override fun onDestroy() {
        super.onDestroy()
        scope.cancel()
    }
}
