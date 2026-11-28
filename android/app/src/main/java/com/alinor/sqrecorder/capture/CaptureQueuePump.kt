package com.alinor.sqrecorder.capture

import android.util.Log
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.locks.LockSupport

/**
 * Single-consumer bridge between the native bounded queue and the encrypted
 * V2 WAV sink. Plaintext PCM exists only in bounded memory, not in a staging file.
 *
 * AudioRecord's producer never waits for disk I/O; native submit is bounded and
 * fail-closed. Any queue/sink error is surfaced to the capture owner, which
 * must preserve the .part file and must not finalize it as a successful take.
 */
internal class CaptureQueuePump(
    private val queue: JniCaptureQueue,
    private val sampleRateHz: Int,
    private val output: SqveV2EncryptedWavSink,
    private val captureEpoch: Long,
    private val onConsumerFailure: (Throwable) -> Unit = {},
) : AutoCloseable {
    private val drainRequested = AtomicBoolean(false)
    private val consumerFailure = AtomicReference<Throwable?>(null)
    private val consumerDone = AtomicBoolean(false)
    private val closed = AtomicBoolean(false)
    private val consumer = Thread({ consume() }, "sqrec-pcm-sink").apply {
        priority = Thread.NORM_PRIORITY
    }

    private var producerFrameIndex = 0L
    private var producerSequence = 1
    private var consumerFrameIndex = 0L
    private var consumerSequence = 1

    fun start() {
        check(!consumer.isAlive && !consumerDone.get()) { "PCM consumer already started" }
        consumer.start()
    }

    /** Called only by the AudioRecord thread with a reused direct buffer. */
    fun submit(
        pcm: ByteBuffer,
        byteCount: Int,
        frameCount: Int,
        monotonicTimestampNs: Long,
    ) {
        consumerFailure.get()?.let { throw IllegalStateException("PCM consumer failed", it) }
        check(!drainRequested.get()) { "PCM queue is already stopping" }
        check(byteCount > 0 && byteCount % 2 == 0 && frameCount == byteCount / 2)
        val status = queue.submit(
            pcm = pcm,
            sampleRateHz = sampleRateHz,
            byteCount = byteCount,
            frameCount = frameCount,
            firstFrameIndex = producerFrameIndex,
            monotonicTimestampNs = monotonicTimestampNs,
            captureEpoch = captureEpoch,
            sequence = producerSequence,
        )
        if (status != JniCaptureQueue.STATUS_OK) {
            val error = IllegalStateException("native PCM submit failed with sq_status_v1=$status")
            consumerFailure.compareAndSet(null, error)
            throw error
        }
        producerFrameIndex = Math.addExact(producerFrameIndex, frameCount.toLong())
        producerSequence = Math.addExact(producerSequence, 1)
        LockSupport.unpark(consumer)
    }

    /** Stops producers, drains both native rings, and verifies native final state. */
    fun stopAndDrain() {
        if (drainRequested.compareAndSet(false, true)) {
            val status = queue.requestStop()
            if (status != JniCaptureQueue.STATUS_OK) {
                consumerFailure.compareAndSet(
                    null,
                    IllegalStateException("native request-stop failed with sq_status_v1=$status"),
                )
            }
        }
        consumer.join()
        val failure = consumerFailure.get()
        queue.close()
        closed.set(true)
        if (failure != null) throw IllegalStateException("bounded PCM drain/finalize failed", failure)
        check(consumerDone.get()) { "native PCM consumer exited without a verified finish" }
    }

    private fun consume() {
        val pcm = ByteBuffer.allocateDirect(MAX_BLOCK_BYTES)
        val metadataBytes = ByteArray(JniCaptureQueue.PCM_BLOCK_METADATA_BYTES)
        val eventBytes = ByteArray(JniCaptureQueue.EVENT_METADATA_BYTES)
        val stagingBytes = ByteArray(MAX_BLOCK_BYTES)
        try {
            while (true) {
                drainEvents(eventBytes)
                val byteCount = queue.readPcm(pcm, metadataBytes)
                if (byteCount == JniCaptureQueue.STATUS_WOULD_BLOCK.toLong()) {
                    if (drainRequested.get()) {
                        val finishStatus = queue.finish()
                        check(finishStatus == JniCaptureQueue.STATUS_OK) {
                            "native finish failed with sq_status_v1=$finishStatus"
                        }
                        consumerDone.set(true)
                        return
                    }
                    LockSupport.parkNanos(this, CONSUMER_IDLE_PARK_NS)
                    continue
                }
                check(byteCount > 0L) { "native PCM dequeue failed with sq_status_v1=$byteCount" }
                val metadata = JniCaptureQueue.decodePcmMetadata(metadataBytes)
                check(metadata.sampleRateHz == sampleRateHz && metadata.channels == 1 &&
                    metadata.sampleFormat == 1 && metadata.payloadBytes == byteCount &&
                    metadata.captureEpoch == captureEpoch &&
                    metadata.firstFrameIndex == consumerFrameIndex &&
                    metadata.sequence == consumerSequence
                ) { "native PCM metadata discontinuity; retain partial and mark integrity failure" }
                check(byteCount <= stagingBytes.size.toLong() && byteCount % 2L == 0L)
                pcm.position(0)
                pcm.get(stagingBytes, 0, byteCount.toInt())
                output.writePcm(stagingBytes, 0, byteCount.toInt())
                consumerFrameIndex = Math.addExact(consumerFrameIndex, metadata.frameCount.toLong())
                consumerSequence = Math.addExact(consumerSequence, 1)
            }
        } catch (failure: Throwable) {
            val firstFailure = consumerFailure.compareAndSet(null, failure)
            Log.e(TAG, "Bounded encrypted PCM sink failed; encrypted partial must remain recoverable", failure)
            // Notify capture control immediately. The producer may be blocked in
            // AudioRecord.READ_BLOCKING; stopping it is required to unblock read
            // and enter the single capture-thread drain/finalization path.
            if (firstFailure) {
                try {
                    onConsumerFailure(failure)
                } catch (callbackFailure: Throwable) {
                    Log.e(TAG, "Capture failure callback failed", callbackFailure)
                }
            }
        } finally {
            consumerDone.set(true)
        }
    }

    private fun drainEvents(buffer: ByteArray) {
        while (true) {
            val status = queue.readEvent(buffer)
            if (status == JniCaptureQueue.STATUS_WOULD_BLOCK) return
            check(status == JniCaptureQueue.STATUS_OK) {
                "native capture event dequeue failed with sq_status_v1=$status"
            }
            // The event ring is metadata-only at this slice. Persistence to SQJ
            // is a required later integration; do not claim journal durability.
            val event = JniCaptureQueue.decodeEventMetadata(buffer)
            Log.i(TAG, "Capture integrity event type=${event.eventType}, sequence=${event.eventSequence}, code=${event.detailCode}")
        }
    }

    override fun close() {
        if (!closed.get()) stopAndDrain()
    }

    private companion object {
        const val TAG = "SQRecorderQueuePump"
        const val MAX_BLOCK_BYTES = 256 * 1024
        const val CONSUMER_IDLE_PARK_NS = 500_000L
    }
}
