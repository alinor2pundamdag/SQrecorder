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
import android.os.SystemClock
import com.alinor.sqrecorder.domain.SessionId
import com.alinor.sqrecorder.domain.SessionLifecycle
import com.alinor.sqrecorder.domain.SessionPhase
import com.alinor.sqrecorder.domain.SessionSnapshot
import com.alinor.sqrecorder.domain.SessionEvent
import com.alinor.sqrecorder.domain.StopReason
import com.alinor.sqrecorder.domain.SessionFailureCode
import com.alinor.sqrecorder.domain.TransitionOutcome
import com.alinor.sqrecorder.capture.CaptureQueuePump
import com.alinor.sqrecorder.capture.JniCaptureQueue
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean

/**
 * B5 capture slice: foreground microphone capture to app-private PCM WAV.
 * Failed writes/finalization leave a .part recovery artifact, never a success WAV.
 * Journal/Vault/durable-store integration is explicitly not yet wired.
 */
public class CaptureForegroundService : Service() {
 private val stopping = AtomicBoolean(false)
 @Volatile private var stopReason = StopReason.USER_REQUEST
 @Volatile private var captureThread: Thread? = null
 @Volatile private var recorder: AudioRecord? = null
 @Volatile private var output: RandomAccessFile? = null

 override fun onCreate() { super.onCreate(); createNotificationChannel() }

 override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
  when (intent?.action) {
   ACTION_STOP -> { stopReason = StopReason.USER_REQUEST; stopping.set(true) }
   ACTION_START -> if (captureThread == null) {
    if (Build.VERSION.SDK_INT >= 29) startForeground(NOTIFICATION_ID, notification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE)
    else startForeground(NOTIFICATION_ID, notification())
    stopping.set(false)
    stopReason = StopReason.USER_REQUEST
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
  var pump: CaptureQueuePump? = null
  var session = SessionSnapshot.create(SessionId(java.util.UUID.randomUUID().toString()), SystemClock.elapsedRealtimeNanos())
  fun reduce(event: SessionEvent) {
   when (val result = SessionLifecycle.reduce(session, event)) {
    is TransitionOutcome.Applied -> session = result.snapshot
    is TransitionOutcome.Rejected -> error("Session lifecycle rejected event: ${result.error}")
   }
  }
  try {
   reduce(SessionEvent.PreparationSucceeded(SystemClock.elapsedRealtimeNanos()))
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
   reduce(SessionEvent.CaptureStarted(SystemClock.elapsedRealtimeNanos(), 1L))

   // Route AudioRecord through the fixed native queue. Disk writes are isolated
   // to the consumer thread; overflow/contention fails closed and retains .part.
   val queue = JniCaptureQueue(
    sampleRateHz = rate,
    queueBlockCapacity = QUEUE_BLOCK_CAPACITY,
    maxBlockFrames = MAX_CAPTURE_BLOCK_FRAMES,
   )
   pump = CaptureQueuePump(queue, rate, output!!, 1L)
   pump!!.start()
   val pcm = ByteBuffer.allocateDirect(MAX_CAPTURE_BLOCK_BYTES)
   var bytes = 0L
   while (!stopping.get()) {
    if (StatFs(filesDir.absolutePath).availableBytes < MIN_FREE_BYTES) {
     stopping.set(true) // deterministic low-storage stop
     stopReason = StopReason.STORAGE_LIMIT
     break
    }
    pcm.clear()
    val count = active.read(pcm, pcm.capacity(), AudioRecord.READ_BLOCKING)
    if (count < 0) throw IllegalStateException("AudioRecord read failed: $count")
    if (count == 0) continue
    if (count % 2 != 0) throw IllegalStateException("AudioRecord returned a partial S16 frame: $count bytes")
    pcm.position(0)
    pump!!.submit(pcm, count, count / 2, SystemClock.elapsedRealtimeNanos())
    bytes = Math.addExact(bytes, count.toLong())
   }
   reduce(SessionEvent.StopRequested(SystemClock.elapsedRealtimeNanos(), stopReason))
   active.stop()
   pump!!.stopAndDrain()
   pump = null
   reduce(SessionEvent.CaptureStopped(SystemClock.elapsedRealtimeNanos()))
   check(bytes > 0L && bytes % 2L == 0L) { "No complete PCM frames captured; partial retained" }
   output!!.seek(0)
   output!!.write(PcmWavHeader.create(rate, bytes))
   output!!.fd.sync()
   output!!.close()
   output = null
   val destination = File(partial.parentFile, partial.name.removeSuffix(".part"))
   check(partial.renameTo(destination)) { "Finalize rename failed; partial file retained" }
   reduce(SessionEvent.FinalizationSucceeded(SystemClock.elapsedRealtimeNanos(), bytes + 44L))
   success = true
  } catch (failure: Exception) {
   try {
    if (session.phase == SessionPhase.FINALIZING) reduce(SessionEvent.FinalizationFailed(SystemClock.elapsedRealtimeNanos(), SessionFailureCode.FINALIZATION_FAILED))
    else if (session.phase !in setOf(SessionPhase.FINALIZED, SessionPhase.FAILED, SessionPhase.RECOVERED)) reduce(SessionEvent.Failed(SystemClock.elapsedRealtimeNanos(), SessionFailureCode.CAPTURE_PIPELINE_FAILED))
   } catch (_: Exception) { }
   android.util.Log.e(TAG, "Capture/finalization failed; preserve partial artifact", failure)
  } finally {
   try { if (active?.recordingState == AudioRecord.RECORDSTATE_RECORDING) active.stop() } catch (_: Exception) {}
   active?.release()
   recorder = null
   try { pump?.stopAndDrain() } catch (pumpFailure: Exception) {
    success = false
    android.util.Log.e(TAG, "Native queue did not drain cleanly; preserve partial artifact", pumpFailure)
   }
   pump = null
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
  private const val QUEUE_BLOCK_CAPACITY = 32
  private const val MAX_CAPTURE_BLOCK_FRAMES = 32_768
  private const val MAX_CAPTURE_BLOCK_BYTES = MAX_CAPTURE_BLOCK_FRAMES * 2
 }
}
