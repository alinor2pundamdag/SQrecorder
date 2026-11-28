package com.alinor.sqrecorder.capture

import com.alinor.sqrecorder.PcmWavHeader
import com.alinor.sqrecorder.domain.VaultFileKeyHandle
import com.alinor.sqrecorder.vault.android.VaultNativeKeyBridge
import java.io.RandomAccessFile
import java.security.MessageDigest

/**
 * Capture-time encrypted WAV sink. It never creates a plaintext WAV file:
 * PCM is held in two bounded 1 MiB buffers and encrypted through the Rust
 * native chunk primitive. The first chunk is reserved until Stop so the final
 * RIFF/data lengths can be patched in memory before its first AEAD operation.
 */
internal class SqveV2EncryptedWavSink(
    private val file: RandomAccessFile,
    private val native: VaultNativeKeyBridge,
    private val keyHandle: VaultFileKeyHandle,
    private val fileId: ByteArray,
    private val fileSalt: ByteArray,
    private val noncePrefix: ByteArray,
    headerBytes: ByteArray,
    private val sampleRateHz: Int,
) : AutoCloseable {
    private val header = headerBytes.copyOf()
    private val firstChunk = ByteArray(CHUNK_BYTES)
    private val tailChunk = ByteArray(CHUNK_BYTES)
    private var firstUsed = 0
    private var tailUsed = 0
    private var firstReserved = false
    private var firstRecordOffset = header.size.toLong()
    private var nextIndex = 1L
    private var closed = false

    init {
        require(fileId.size == 16 && fileSalt.size == 32 && noncePrefix.size == 4)
        require(header.isNotEmpty())
        file.setLength(0L)
        file.write(header)
        // A canonical 44-byte WAV header is written into the first encrypted
        // chunk buffer; final RIFF/data lengths are patched before encryption.
        val wavHeader = PcmWavHeader.create(sampleRateHz, 0L)
        wavHeader.copyInto(firstChunk, 0)
        firstUsed = wavHeader.size
        wavHeader.fill(0)
    }

    fun writePcm(bytes: ByteArray, offset: Int, length: Int) {
        check(!closed) { "encrypted WAV sink is closed" }
        require(offset >= 0 && length >= 0 && offset + length <= bytes.size)
        var cursor = offset
        var remaining = length
        while (remaining > 0) {
            if (firstUsed < CHUNK_BYTES) {
                val take = minOf(CHUNK_BYTES - firstUsed, remaining)
                bytes.copyInto(firstChunk, firstUsed, cursor, cursor + take)
                firstUsed += take
                cursor += take
                remaining -= take
                if (firstUsed == CHUNK_BYTES) reserveFirstChunkSlot()
                continue
            }
            val take = minOf(CHUNK_BYTES - tailUsed, remaining)
            bytes.copyInto(tailChunk, tailUsed, cursor, cursor + take)
            tailUsed += take
            cursor += take
            remaining -= take
            if (tailUsed == CHUNK_BYTES) emitTailChunk(CHUNK_BYTES)
        }
    }

    private fun reserveFirstChunkSlot() {
        if (firstReserved) return
        firstReserved = true
        // Reserve exact record + ciphertext + tag size. This keeps later chunk
        // indices physically ordered while chunk zero remains in bounded RAM.
        file.seek(firstRecordOffset + CHUNK_RECORD_BYTES + CHUNK_BYTES + GCM_TAG_BYTES)
    }

    fun finish(pcmBytes: Long): Long {
        check(!closed) { "encrypted WAV sink already finalized" }
        require(pcmBytes > 0L && pcmBytes % 2L == 0L)
        val wavHeader = PcmWavHeader.create(sampleRateHz, pcmBytes)
        wavHeader.copyInto(firstChunk, 0)
        wavHeader.fill(0)
        val plaintextTotal = Math.addExact(pcmBytes, 44L)

        emitChunk(index = 0L, buffer = firstChunk, size = firstUsed)
        firstChunk.fill(0)
        if (tailUsed > 0) emitTailChunk(tailUsed)

        // Hash the serialized header and encrypted chunk records in wire order.
        val digest = MessageDigest.getInstance("SHA-256")
        file.seek(0L)
        var bytesRemaining = file.filePointerUntilChunks()
        val scratch = ByteArray(HASH_BUFFER_BYTES)
        while (bytesRemaining > 0L) {
            val take = minOf(bytesRemaining, scratch.size.toLong()).toInt()
            file.readFully(scratch, 0, take)
            digest.update(scratch, 0, take)
            scratch.fill(0)
            bytesRemaining -= take
        }
        scratch.fill(0)
        val streamDigest = digest.digest()
        val footerOffset = file.filePointer
        val footer = ByteArray(FOOTER_BYTES)
        "SQVF".toByteArray(Charsets.US_ASCII).copyInto(footer, 0)
        putU16(footer, 4, VERSION)
        putU16(footer, 6, FOOTER_BYTES)
        putU64(footer, 8, nextIndex)
        putU64(footer, 16, plaintextTotal)
        streamDigest.copyInto(footer, 24)
        file.seek(footerOffset)
        file.write(footer)
        file.setLength(footerOffset + FOOTER_BYTES)
        file.fd.sync()
        footer.fill(0)
        streamDigest.fill(0)
        closed = true
        return file.length()
    }

    private fun emitTailChunk(size: Int) {
        emitChunk(nextIndex, tailChunk, size)
        tailChunk.fill(0)
        tailUsed = 0
        nextIndex = Math.addExact(nextIndex, 1L)
    }

    private fun emitChunk(index: Long, buffer: ByteArray, size: Int) {
        require(size in 1..CHUNK_BYTES)
        val nonce = noncePrefix + u64be(index)
        val aad = chunkAad(index, size)
        val plaintext = buffer.copyOfRange(0, size)
        val ciphertextAndTag = try {
            native.encryptChunk(keyHandle, nonce, aad, plaintext)
        } finally {
            plaintext.fill(0)
        }
        require(ciphertextAndTag.size == size + GCM_TAG_BYTES) {
            ciphertextAndTag.fill(0)
            throw IllegalStateException("Native V2 encrypt returned malformed ciphertext")
        }
        val record = ByteArray(CHUNK_RECORD_BYTES)
        "SQVC".toByteArray(Charsets.US_ASCII).copyInto(record, 0)
        putU64(record, 4, index)
        putU32(record, 12, size)
        putU32(record, 16, size + GCM_TAG_BYTES)
        val target = if (index == 0L) firstRecordOffset else file.filePointer
        file.seek(target)
        file.write(record)
        file.write(ciphertextAndTag)
        ciphertextAndTag.fill(0)
        record.fill(0)
        nonce.fill(0)
        aad.fill(0)
        if (index == 0L && firstReserved) {
            file.seek(firstRecordOffset + CHUNK_RECORD_BYTES + CHUNK_BYTES + GCM_TAG_BYTES)
        }
        if (index == 0L) nextIndex = 1L
    }

    private fun chunkAad(index: Long, size: Int): ByteArray =
        DOMAIN + u16be(VERSION) + u16be(CONTENT_SUITE) + fileId + fileSalt +
            noncePrefix + u32be(CHUNK_BYTES) + u64be(-1L) + u64be(index) + u32be(size)

    private fun RandomAccessFile.filePointerUntilChunks(): Long {
        // For reserved chunk zero, later encrypted chunks are already contiguous
        // at their canonical positions; the current length excludes the footer.
        return length()
    }

    override fun close() {
        if (!closed) {
            firstChunk.fill(0)
            tailChunk.fill(0)
            closed = true
        }
        file.close()
    }

    private companion object {
        const val VERSION = 2
        const val CONTENT_SUITE = 1
        const val CHUNK_BYTES = 1_048_576
        const val CHUNK_RECORD_BYTES = 20
        const val GCM_TAG_BYTES = 16
        const val FOOTER_BYTES = 56
        const val HASH_BUFFER_BYTES = 64 * 1024
        val DOMAIN = "SQREC-SQVE2-CHUNK-AAD-v1".toByteArray(Charsets.US_ASCII)
    }
}

private fun u16be(value: Int): ByteArray = byteArrayOf((value ushr 8).toByte(), value.toByte())
private fun u32be(value: Int): ByteArray = byteArrayOf(
    (value ushr 24).toByte(), (value ushr 16).toByte(), (value ushr 8).toByte(), value.toByte(),
)
private fun u64be(value: Long): ByteArray = ByteArray(8) { (value ushr (56 - it * 8)).toByte() }
private fun putU16(out: ByteArray, at: Int, value: Int) { out[at] = (value ushr 8).toByte(); out[at + 1] = value.toByte() }
private fun putU32(out: ByteArray, at: Int, value: Int) { u32be(value).copyInto(out, at) }
private fun putU64(out: ByteArray, at: Int, value: Long) { u64be(value).copyInto(out, at) }
