package com.alinor.sqrecorder

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class PcmWavHeaderTest {
 private fun u32(data: ByteArray, offset: Int): Long =
  (data[offset].toLong() and 0xff) or
   ((data[offset + 1].toLong() and 0xff) shl 8) or
   ((data[offset + 2].toLong() and 0xff) shl 16) or
   ((data[offset + 3].toLong() and 0xff) shl 24)

 @Test fun writesCanonicalMonoPcm48kHeaderAndLengths() {
  val h = PcmWavHeader.create(48_000, 9_600)
  assertEquals(44, h.size)
  assertEquals("RIFF", String(h, 0, 4, Charsets.US_ASCII))
  assertEquals("WAVE", String(h, 8, 4, Charsets.US_ASCII))
  assertEquals(9_636L, u32(h, 4))
  assertEquals(1, h[20].toInt())
  assertEquals(1, h[22].toInt())
  assertEquals(48_000L, u32(h, 24))
  assertEquals(96_000L, u32(h, 28))
  assertEquals(16, h[34].toInt())
  assertEquals(9_600L, u32(h, 40))
 }

 @Test fun rejectsUnsupportedRateAndOverflow() {
  assertThrows(IllegalArgumentException::class.java) { PcmWavHeader.create(32_000, 0) }
  assertThrows(IllegalArgumentException::class.java) { PcmWavHeader.create(48_000, 0x1_0000_0000L) }
 }
}
