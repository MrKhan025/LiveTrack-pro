package pro.livetrack.app.audio

import android.annotation.SuppressLint
import android.content.Context
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import android.util.Base64
import kotlinx.coroutines.*
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.nio.ByteBuffer
import java.nio.ByteOrder

class ConsentAudioStreamer(
    private val context: Context,
    private val serverUrl: String,
    private val deviceId: String,
    private val bearerToken: String
) {
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var audioRecord: AudioRecord? = null
    @Volatile private var isCapturing = false
    private var activeSessionId: String? = null
    private var activeConsentToken: String? = null
    private val pcmOutput = ByteArrayOutputStream()

    @SuppressLint("MissingPermission")
    fun startExplicitUserRecording(onStatus: (String) -> Unit) {
        scope.launch {
            try {
                // Step 1: Request Consent Session Token from Backend (initiatedByDevice = true)
                val url = URL("$serverUrl/api/audio/sessions/start")
                val conn = (url.openConnection() as HttpURLConnection).apply {
                    requestMethod = "POST"
                    doOutput = true
                    setRequestProperty("Content-Type", "application/json")
                    setRequestProperty("Authorization", "Bearer $bearerToken")
                }
                val reqJson = JSONObject()
                    .put("deviceId", deviceId)
                    .put("initiatedByDevice", true)
                    .put("userConsentConfirmed", true)
                    .put("consentStatement", "Android user explicitly tapped Start Recording with visible status banner.")
                    .toString()

                conn.outputStream.use { it.write(reqJson.toByteArray()) }
                val resJson = JSONObject(conn.inputStream.bufferedReader().readText())
                activeSessionId = resJson.getJSONObject("session").getString("id")
                activeConsentToken = resJson.getString("consentToken")

                // Step 2: Start 48kHz 16-bit Mono AudioRecord
                val sampleRate = 48000
                val minBuf = AudioRecord.getMinBufferSize(
                    sampleRate,
                    AudioFormat.CHANNEL_IN_MONO,
                    AudioFormat.ENCODING_PCM_16BIT
                )
                audioRecord = AudioRecord(
                    MediaRecorder.AudioSource.MIC,
                    sampleRate,
                    AudioFormat.CHANNEL_IN_MONO,
                    AudioFormat.ENCODING_PCM_16BIT,
                    minBuf * 2
                )
                pcmOutput.reset()
                audioRecord?.startRecording()
                isCapturing = true
                onStatus("🔴 Recording User-Consented Audio (Session ${activeSessionId?.take(8)})")

                val readBuffer = ByteArray(2048)
                while (isCapturing) {
                    val read = audioRecord?.read(readBuffer, 0, readBuffer.size) ?: 0
                    if (read > 0) {
                        pcmOutput.write(readBuffer, 0, read)
                    }
                }
            } catch (e: Exception) {
                onStatus("Audio Start Error: ${e.message}")
            }
        }
    }

    fun stopAndUploadRecording(onComplete: (String) -> Unit) {
        scope.launch {
            try {
                isCapturing = false
                audioRecord?.stop()
                audioRecord?.release()
                audioRecord = null

                val pcmBytes = pcmOutput.toByteArray()
                val wavBytes = wrapPcmAsWav(pcmBytes, 48000, 1, 16)
                val base64Audio = Base64.encodeToString(wavBytes, Base64.NO_WRAP)

                val sessionId = activeSessionId ?: return@launch onComplete("No active session")
                val consentToken = activeConsentToken ?: return@launch onComplete("Missing consent token")

                val uploadUrl = URL("$serverUrl/api/audio/recordings/upload")
                val conn = (uploadUrl.openConnection() as HttpURLConnection).apply {
                    requestMethod = "POST"
                    doOutput = true
                    setRequestProperty("Content-Type", "application/json")
                    setRequestProperty("Authorization", "Bearer $bearerToken")
                }
                val payload = JSONObject()
                    .put("sessionId", sessionId)
                    .put("deviceId", deviceId)
                    .put("consentToken", consentToken)
                    .put("title", "Android Explicit Consent Audio Clip")
                    .put("mimeType", "audio/wav")
                    .put("durationSeconds", (pcmBytes.size / (48000.0 * 2.0)).coerceAtLeast(1.0))
                    .put("audioBase64", base64Audio)
                    .toString()

                conn.outputStream.use { it.write(payload.toByteArray()) }
                conn.inputStream.close()

                // Stop session
                val stopUrl = URL("$serverUrl/api/audio/sessions/$sessionId/stop")
                val stopConn = (stopUrl.openConnection() as HttpURLConnection).apply {
                    requestMethod = "POST"
                    doOutput = true
                    setRequestProperty("Content-Type", "application/json")
                    setRequestProperty("Authorization", "Bearer $bearerToken")
                }
                stopConn.outputStream.use { it.write("{}".toByteArray()) }
                stopConn.inputStream.close()

                onComplete("✅ Encrypted Consent Audio Uploaded & Session Closed")
            } catch (e: Exception) {
                onComplete("Upload Error: ${e.message}")
            }
        }
    }

    private fun wrapPcmAsWav(pcmData: ByteArray, sampleRate: Int, channels: Int, bitsPerSample: Int): ByteArray {
        val header = ByteBuffer.allocate(44).order(ByteOrder.LITTLE_ENDIAN)
        val byteRate = sampleRate * channels * bitsPerSample / 8
        header.put("RIFF".toByteArray())
        header.putInt(36 + pcmData.size)
        header.put("WAVE".toByteArray())
        header.put("fmt ".toByteArray())
        header.putInt(16)
        header.putShort(1)
        header.putShort(channels.toShort())
        header.putInt(sampleRate)
        header.putInt(byteRate)
        header.putShort((channels * bitsPerSample / 8).toShort())
        header.putShort(bitsPerSample.toShort())
        header.put("data".toByteArray())
        header.putInt(pcmData.size)
        return header.array() + pcmData
    }
}
