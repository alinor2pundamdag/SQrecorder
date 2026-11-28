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
import com.alinor.sqrecorder.capture.SqveV2EncryptedWavSink
import com.alinor.sqrecorder.vault.android.AndroidSqveV2HeaderCodec
import com.alinor.sqrecorder.vault.android.AndroidSqveV2KeyAccess
import com.alinor.sqrecorder.vault.android.JniVaultNativeKeyBridge
import com.alinor.sqrecorder.vault.android.VaultAuthContextVerifier
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean

/**
 * B5 capture slice: foreground microphone capture into a bounded-memory SQVE v2
 * encrypted WAV stream. Journal/durable-store promotion and authenticated recovery
 * are separate release gates; failed finalization retains only an encrypted .part.
 */
public class CaptureForegroundService : Service() {
 private val stopping = AtomicBoolean(false)
 @Volatile private var stopReason = StopReason.USER_REQUEST
 @Volatile private var captureThread: Thread? = null
 @Volatile private var recorder: AudioRecord? = null
 @Volatile private var encryptedSink: SqveV2EncryptedWavSink? = null
 @Volatile private var vaultNative: JniVaultNativeKeyBridge? = null
 @Volatile private var vaultKeyHandle: com.alinor.sqrecorder.domain.VaultFileKeyHandle? = null

 override fun onCreate() { super.onCreate(); createNotificationChannel() }

 override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
  when (intent?.action) {
   ACTION_STOP -> requestStop(StopReason.USER_REQUEST)
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
  var producerPcm: ByteBuffer? = null
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
   // UUID plus explicit truncate prevents timestamp collisions from reusing
   // stale tail bytes in a previous .part file.
   partial = File(directory, "capture-" + java.util.UUID.randomUUID() + ".sqve.part")
   val nativeVault = JniVaultNativeKeyBridge()
   vaultNative = nativeVault
   // Capture only needs the recipient's public key. This verifier deliberately
   // rejects decrypt until the app's authenticated recovery flow is integrated.
   val v2Keys = AndroidSqveV2KeyAccess(nativeVault, VaultAuthContextVerifier { false })
   val fileKeyHandle = v2Keys.createRandomV2FileKeyHandle()
   vaultKeyHandle = fileKeyHandle
   val secureRandom = java.security.SecureRandom()
   val fileId = ByteArray(16).also(secureRandom::nextBytes)
   val fileSalt = ByteArray(32).also(secureRandom::nextBytes)
   val noncePrefix = ByteArray(4).also(secureRandom::nextBytes)
   val recipientId = v2Keys.currentPublicV2RecipientKeyId()
   val recipientWrap = v2Keys.wrapFileKeyForV2(fileKeyHandle, recipientId, fileId, fileSalt)
   val headerBytes = AndroidSqveV2HeaderCodec(nativeVault).serializeStreamingHeader(
    fileKeyHandle, fileId, fileSalt, noncePrefix, recipientWrap)
   encryptedSink = SqveV2EncryptedWavSink(
    RandomAccessFile(partial, "rw"), nativeVault, fileKeyHandle,
    fileId, fileSalt, noncePrefix, headerBytes, rate)
   headerBytes.fill(0)
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
   pump = CaptureQueuePump(queue, rate, encryptedSink!!, 1L) { failure ->
    android.util.Log.e(TAG, "PCM sink failed; requesting controlled capture stop", failure)
    requestStop(StopReason.CAPTURE_FAILURE)
   }
   pump!!.start()
   val pcm = ByteBuffer.allocateDirect(MAX_CAPTURE_BLOCK_BYTES)
   producerPcm = pcm
   var bytes = 0L
   while (!stopping.get()) {
    if (StatFs(filesDir.absolutePath).availableBytes < MIN_FREE_BYTES) {
     // READ_BLOCKING can hang after only setting the stop flag.
     // Stop AudioRecord now so the read returns and cleanup drains the queue.
     requestStop(StopReason.STORAGE_LIMIT)
     break
    }
    pcm.clear()
    val count = active.read(pcm, pcm.capacity(), AudioRecord.READ_BLOCKING)
    if (count < 0) {
     if (stopping.get()) break // requestStop() intentionally unblocks READ_BLOCKING
     throw IllegalStateException("AudioRecord read failed: $count")
    }
    if (count == 0) continue
    if (count % 2 != 0) throw IllegalStateException("AudioRecord returned a partial S16 frame: $count bytes")
    if (bytes > MAX_WAV_PCM_BYTES - count.toLong()) {
     requestStop(StopReason.STORAGE_LIMIT)
     break
    }
    pcm.position(0)
    pump!!.submit(pcm, count, count / 2, SystemClock.elapsedRealtimeNanos())
    bytes = Math.addExact(bytes, count.toLong())
   }
   reduce(SessionEvent.StopRequested(SystemClock.elapsedRealtimeNanos(), stopReason))
   stopRecorderIfRecording(active)
   pump!!.stopAndDrain()
   pump = null
   reduce(SessionEvent.CaptureStopped(SystemClock.elapsedRealtimeNanos()))
   check(bytes > 0L && bytes % 2L == 0L) { "No complete PCM frames captured; encrypted partial retained" }
   val encryptedBytes = encryptedSink!!.finish(bytes)
   encryptedSink!!.close()
   encryptedSink = null
   nativeVault.destroyFileKeyHandle(fileKeyHandle)
   vaultKeyHandle = null
   fileId.fill(0); fileSalt.fill(0); noncePrefix.fill(0)
   val destination = File(partial.parentFile, partial.name.removeSuffix(".part"))
   check(partial.renameTo(destination)) { "Encrypted finalize rename failed; partial retained" }
   reduce(SessionEvent.FinalizationSucceeded(SystemClock.elapsedRealtimeNanos(), encryptedBytes))
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
   producerPcm?.let { buffer ->
    buffer.clear()
    while (buffer.hasRemaining()) buffer.put(0)
   }
   producerPcm = null
   try { encryptedSink?.close() } catch (_: Exception) {}
   encryptedSink = null
   vaultKeyHandle?.let { handle ->
    try { vaultNative?.destroyFileKeyHandle(handle) } catch (failure: Exception) {
     android.util.Log.e(TAG, "Native V2 key-handle cleanup failed", failure)
    }
   }
   vaultKeyHandle = null
   vaultNative = null
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

 /**
  * AudioRecord.READ_BLOCKING may not return merely because the stop flag changed.
  * Stop the active recorder from the service control thread to unblock the
  * capture read; captureLoop then owns queue drain and finalization.
  */
 private fun requestStop(reason: StopReason) {
  stopReason = reason
  stopping.set(true)
  recorder?.let { stopRecorderIfRecording(it) }
 }

 private fun stopRecorderIfRecording(active: AudioRecord) {
  try {
   if (active.recordingState == AudioRecord.RECORDSTATE_RECORDING) active.stop()
  } catch (failure: IllegalStateException) {
   // A concurrent stop/read transition can make stop invalid; finalization
   // still proceeds through the single capture-thread cleanup path.
   android.util.Log.w(TAG, "AudioRecord stop raced with capture shutdown", failure)
  }
 }

 override fun onDestroy() {
  requestStop(StopReason.USER_REQUEST)
  super.onDestroy()
 }

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
  private const val MAX_WAV_PCM_BYTES = 0xffff_ffffL - 36L
 }
}
