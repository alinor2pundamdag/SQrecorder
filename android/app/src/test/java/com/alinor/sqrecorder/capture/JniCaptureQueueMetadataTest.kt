package com.alinor.sqrecorder.capture

import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Assert.assertEquals
import org.junit.Test

class JniCaptureQueueMetadataTest {
    @Test
    fun decodesPcmMetadataUsingNativeAbiOffsets() {
        val bytes = ByteArray(64)
        ByteBuffer.wrap(bytes).order(ByteOrder.nativeOrder()).apply {
            putInt(0, 64)
            putInt(8, 48_000)
            putShort(12, 1)
            putShort(14, 1)
            putInt(16, 240)
            putLong(24, 12_345)
            putLong(32, 77_000)
            putLong(40, 9)
            putLong(48, 480)
            putInt(56, 3)
        }
        assertEquals(
            PcmBlockMetadata(48_000, 1, 1, 240, 12_345, 77_000, 9, 480, 3),
            JniCaptureQueue.decodePcmMetadata(bytes),
        )
    }

    @Test
    fun decodesCaptureEventMetadata() {
        val bytes = ByteArray(48)
        ByteBuffer.wrap(bytes).order(ByteOrder.nativeOrder()).apply {
            putInt(0, 48)
            putInt(4, 3)
            putLong(16, 6)
            putLong(24, 123)
            putLong(32, 7)
            putInt(40, 2)
        }
        assertEquals(
            CaptureEventMetadata(3, 6, 123, 7, 2),
            JniCaptureQueue.decodeEventMetadata(bytes),
        )
    }
}
