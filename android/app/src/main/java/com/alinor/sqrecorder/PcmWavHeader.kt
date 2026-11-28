package com.alinor.sqrecorder

/** RIFF/WAVE PCM16 mono header writer; finalized only after data length is known. */
internal object PcmWavHeader {
 fun create(sampleRate: Int, dataBytes: Long): ByteArray {
  require(sampleRate in setOf(48_000, 44_100))
  require(dataBytes >= 0L && dataBytes <= 0xffff_ffffL - 36L)
  val bytes = ByteArray(44)
  fun ascii(offset: Int, value: String) = value.toByteArray(Charsets.US_ASCII).copyInto(bytes, offset)
  fun u16(offset: Int, value: Int) {
   bytes[offset] = value.toByte(); bytes[offset + 1] = (value ushr 8).toByte()
  }
  fun u32(offset: Int, value: Long) {
   for (index in 0..3) bytes[offset + index] = (value ushr (8 * index)).toByte()
  }
  ascii(0, "RIFF"); u32(4, dataBytes + 36); ascii(8, "WAVE")
  ascii(12, "fmt "); u32(16, 16); u16(20, 1); u16(22, 1)
  u32(24, sampleRate.toLong()); u32(28, sampleRate.toLong() * 2L)
  u16(32, 2); u16(34, 16); ascii(36, "data"); u32(40, dataBytes)
  return bytes
 }
}
