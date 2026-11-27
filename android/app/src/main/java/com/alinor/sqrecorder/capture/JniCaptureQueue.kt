package com.alinor.sqrecorder.capture

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Thin JNI adapter for the bounded native PCM/event queues.
 *
 * PCM buffers must be direct and preallocated by the caller. This class does not
 * persist audio and must not be mistaken for the encrypted recording pipeline.
 */
public class JniCaptureQueue(
    sampleRateHz: Int,
    queueBlockCapacity: Int,
    maxBlockFrames: Int,
) : AutoCloseable {
    private var handle: Long = nativeCreate(sampleRateHz, queueBlockCapacity, maxBlockFrames)

    init {
        check(handle > 0L) { "native capture queue handle was not created" }
    }

    /** Copies one PCM block into fixed native storage; no queue growth is permitted. */
    public fun submit(
        pcm: ByteBuffer,
        sampleRateHz: Int,
        byteCount: Int,
        frameCount: Int,
        firstFrameIndex: Long,
        monotonicTimestampNs: Long,
        captureEpoch: Long,
        sequence: Int,
    ): Int {
        checkOpen()
        require(pcm.isDirect) { "PCM input must use a direct ByteBuffer" }
        require(byteCount in 1..pcm.capacity())
        require(frameCount > 0 && byteCount == frameCount * PCM_BYTES_PER_FRAME)
        return nativeSubmit(
            handle, pcm, sampleRateHz, byteCount, frameCount, firstFrameIndex,
            monotonicTimestampNs, captureEpoch, sequence,
        )
    }

    /**
     * Dequeues one block into a caller-owned direct buffer.
     * Returns byte count on success or a stable negative sq_status_v1 value.
     */
    public fun readPcm(pcm: ByteBuffer, metadataOut: ByteArray): Long {
        checkOpen()
        require(pcm.isDirect) { "PCM output must use a direct ByteBuffer" }
        require(metadataOut.size >= PCM_BLOCK_METADATA_BYTES)
        return nativeRead(handle, pcm, metadataOut, pcm.capacity())
    }

    public fun pushEvent(
        eventType: Int,
        sequence: Long,
        monotonicTimestampNs: Long,
        captureEpoch: Long,
        detailCode: Int,
    ): Int {
        checkOpen()
        return nativePushEvent(handle, eventType, sequence, monotonicTimestampNs, captureEpoch, detailCode)
    }

    /** Writes the native ABI event struct to the supplied fixed-size output array. */
    public fun readEvent(metadataOut: ByteArray): Int {
        checkOpen()
        require(metadataOut.size >= EVENT_METADATA_BYTES)
        return nativeReadEvent(handle, metadataOut)
    }

    public fun requestStop(): Int {
        checkOpen()
        return nativeRequestStop(handle)
    }

    /** Succeeds only after PCM and event queues have both been drained. */
    public fun finish(): Int {
        checkOpen()
        return nativeFinish(handle)
    }

    public fun state(): Int {
        checkOpen()
        return nativeState(handle)
    }

    override fun close() {
        val current = handle
        if (current != 0L) {
            handle = 0L
            nativeDestroy(current)
        }
    }

    private fun checkOpen() {
        check(handle != 0L) { "native capture queue is closed" }
    }

    public companion object {
        public const val STATUS_OK: Int = 0
        public const val STATUS_WOULD_BLOCK: Int = -5
        public const val PCM_BLOCK_METADATA_BYTES: Int = 64
        public const val EVENT_METADATA_BYTES: Int = 48
        private const val PCM_BYTES_PER_FRAME: Int = 2

        init {
            System.loadLibrary("sqrec_native_abi")
        }
    }

    private external fun nativeCreate(sampleRateHz: Int, queueBlockCapacity: Int, maxBlockFrames: Int): Long
    private external fun nativeSubmit(
        handle: Long,
        pcm: ByteBuffer,
        sampleRateHz: Int,
        byteCount: Int,
        frameCount: Int,
        firstFrameIndex: Long,
        monotonicTimestampNs: Long,
        captureEpoch: Long,
        sequence: Int,
    ): Int
    private external fun nativeRead(handle: Long, pcm: ByteBuffer, metadata: ByteArray, capacity: Int): Long
    private external fun nativePushEvent(
        handle: Long, eventType: Int, sequence: Long, monotonicTimestampNs: Long,
        captureEpoch: Long, detailCode: Int,
    ): Int
    private external fun nativeReadEvent(handle: Long, metadata: ByteArray): Int
    private external fun nativeRequestStop(handle: Long): Int
    private external fun nativeFinish(handle: Long): Int
    private external fun nativeState(handle: Long): Int
    private external fun nativeDestroy(handle: Long)
}
