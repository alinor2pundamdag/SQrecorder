package com.alinor.sqrecorder

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import android.os.Build
import android.os.IBinder
import android.os.Process
import android.os.StatFs
import java.io.File
import java.io.RandomAccessFile
import java.util.concurrent.atomic.AtomicBoolean

/**
 * B5 capture slice: foreground microphone capture to app-private PCM WAV.
 * Failed writes/finalization leave a .part recovery artifact, never a success WAV.
 * Journal/Vault/durable-store integration is explicitly not yet wired.
 */
public class CaptureForegroundService : Service() {
 private val stopping = AtomicBoolean(false)
 @Volatile private var captureThread: Thread? = null
 @Volatile private var recorder: AudioRecord? = null
 @Volatile private var output: RandomAccessFile? = null

 override fun onCreate() { super.onCreate(); createNotificationChannel() }

 override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
  when (intent?.action) {
   ACTION_STOP -> stopping.set(true)
   ACTION_START -> if (captureThread == null) {
    if (Build.VERSION.SDK_INT >= 29) startForeground(NOTIFICATION_ID, notification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE)
    else startForeground(NOTIFICATION_ID, notification())
    stopping.set(false)
    captureThread = Thread({ captureLoop() }, "sqrec-audio-capture").apply {
     priority = Process.THREAD_PRIORITY_AUDIO
     start()
    }
   }
   else -> stopSelf(startId)
  }
  return START_NOT_STICKY
 }

 private fun captureLoop() {
  var active: AudioRecord? = null
  var partial: File? = null
  var success = false
  try {
   var rate = 0
   var bufferSize = 0
   for (candidate in intArrayOf(48_000, 44_100)) {
    val minimum = AudioRecord.getMinBufferSize(candidate, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT)
    if (minimum <= 0) continue
    val candidateBuffer = maxOf(minimum * 2, candidate / 25 * 2)
    val candidateRecorder = try {
     AudioRecord(MediaRecorder.AudioSource.MIC, candidate, AudioFormat.CHANNEL_IN_MONO,
      AudioFormat.ENCODING_PCM_16BIT, candidateBuffer)
    } catch (_: Exception) { continue }
    if (candidateRecorder.state == AudioRecord.STATE_INITIALIZED) {
     active = candidateRecorder
     rate = candidate
     bufferSize = candidateBuffer
     break
    }
    candidateRecorder.release()
   }
   check(active != null) { "48 kHz and 44.1 kHz AudioRecord initialization failed" }
   recorder = active
   val directory = File(filesDir, "recordings")
   check(directory.exists() || directory.mkdirs()) { "Private recordings directory unavailable" }
   partial = File(directory, "capture-" + System.currentTimeMillis() + ".wav.part")
   output = RandomAccessFile(partial, "rw")
   output!!.write(PcmWavHeader.create(rate, 0L))
   active.startRecording()
   check(active.recordingState == AudioRecord.RECORDSTATE_RECORDING) { "AudioRecord start failed" }

   val pcm = ByteArray(bufferSize)
   var bytes = 0L
   while (!stopping.get()) {
    if (StatFs(filesDir.absolutePath).availableBytes < MIN_FREE_BYTES) {
     stopping.set(true) // deterministic low-storage stop
     break
    }
    val count = active.read(pcm, 0, pcm.size, AudioRecord.READ_BLOCKING)
    if (count < 0) throw IllegalStateException("AudioRecord read failed: $count")
    if (count == 0) continue
    output!!.write(pcm, 0, count)
    bytes = Math.addExact(bytes, count.toLong())
   }
   active.stop()
   output!!.seek(0)
   output!!.write(PcmWavHeader.create(rate, bytes))
   output!!.fd.sync()
   output!!.close()
   output = null
   val destination = File(partial.parentFile, partial.name.removeSuffix(".part"))
   check(partial.renameTo(destination)) { "Finalize rename failed; partial file retained" }
   success = true
  } catch (failure: Exception) {
   android.util.Log.e(TAG, "Capture/finalization failed; preserve partial artifact", failure)
  } finally {
   try { if (active?.recordingState == AudioRecord.RECORDSTATE_RECORDING) active.stop() } catch (_: Exception) {}
   active?.release()
   recorder = null
   try { output?.fd?.sync() } catch (_: Exception) {}
   try { output?.close() } catch (_: Exception) {}
   output = null
   captureThread = null
   android.util.Log.i(TAG, if (success) "Capture finalized" else "Capture incomplete; recovery file may exist")
   if (Build.VERSION.SDK_INT >= 24) stopForeground(STOP_FOREGROUND_REMOVE) else stopForeground(true)
   stopSelf()
  }
 }

 private fun createNotificationChannel() {
  if (Build.VERSION.SDK_INT >= 26) {
   getSystemService(NotificationManager::class.java).createNotificationChannel(
    NotificationChannel(CHANNEL_ID, "SQRecorder capture", NotificationManager.IMPORTANCE_LOW)
     .apply { description = "Persistent notice while microphone capture is active" }
   )
  }
 }

 private fun notification(): Notification {
  val stop = PendingIntent.getService(this, 1,
   Intent(this, CaptureForegroundService::class.java).setAction(ACTION_STOP),
   PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
  val builder = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(this, CHANNEL_ID) else Notification.Builder(this)
  return builder.setSmallIcon(android.R.drawable.ic_btn_speak_now)
   .setContentTitle("SQRecorder is recording")
   .setContentText("Microphone active · tap Stop to finalize")
   .setOngoing(true).addAction(android.R.drawable.ic_media_pause, "Stop", stop).build()
 }

 override fun onBind(intent: Intent?): IBinder? = null
 override fun onDestroy() { stopping.set(true); super.onDestroy() }

 companion object {
  const val ACTION_START = "com.alinor.sqrecorder.action.START"
  const val ACTION_STOP = "com.alinor.sqrecorder.action.STOP"
  private const val TAG = "SQRecorderCapture"
  private const val CHANNEL_ID = "sqrec_capture"
  private const val NOTIFICATION_ID = 6101
  private const val MIN_FREE_BYTES = 50L * 1024L * 1024L
 }
}
