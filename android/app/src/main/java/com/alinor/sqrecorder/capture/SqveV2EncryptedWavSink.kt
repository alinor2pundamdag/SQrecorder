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

        // Chunk zero is patched and encrypted at Stop. Preserve the already
        // emitted tail end while overwriting its reserved first-chunk slot.
        val tailEndOffset = if (firstReserved) file.length() else -1L
        emitChunk(index = 0L, buffer = firstChunk, size = firstUsed)
        firstChunk.fill(0)
        if (firstReserved) file.seek(tailEndOffset)
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

    /**
     * Verify the complete staged envelope before the owner may promote it.
     * This re-authenticates the header MAC and every GCM chunk, checks the
     * footer digest/count/length and the canonical WAV size fields.
     */
    fun verifyFinished(pcmBytes: Long) {
        check(!closed) { "sink must remain open until staged verification completes" }
        require(pcmBytes > 0L && pcmBytes % 2L == 0L)
        val expectedPlaintext = Math.addExact(pcmBytes, 44L)
        val totalFileBytes = file.length()
        require(totalFileBytes >= header.size + FOOTER_BYTES)
        file.seek(0L)
        val encodedHeader = ByteArray(header.size)
        file.readFully(encodedHeader)
        require(encodedHeader.contentEquals(header))
        val declaredHeaderLength = readU32(encodedHeader, 6)
        require(declaredHeaderLength == header.size.toLong())
        verifyHeaderMac(encodedHeader)

        val footerOffset = totalFileBytes - FOOTER_BYTES
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(encodedHeader)
        var cursor = encodedHeader.size.toLong()
        var index = 0L
        var plaintextTotal = 0L
        var sawShort = false
        val record = ByteArray(CHUNK_RECORD_BYTES)
        while (cursor < footerOffset) {
            require(!sawShort && footerOffset - cursor >= CHUNK_RECORD_BYTES)
            file.seek(cursor)
            file.readFully(record)
            require(record.copyOfRange(0, 4).contentEquals("SQVC".toByteArray(Charsets.US_ASCII)))
            require(readU64(record, 4) == index)
            val plainLen = readU32(record, 12).toInt()
            val cipherLen = readU32(record, 16).toInt()
            require(plainLen in 1..CHUNK_BYTES && cipherLen == plainLen + GCM_TAG_BYTES)
            if (index > 0L) require(plainLen == CHUNK_BYTES || cursor + CHUNK_RECORD_BYTES + cipherLen == footerOffset)
            sawShort = plainLen < CHUNK_BYTES
            val ciphertext = ByteArray(plainLen + GCM_TAG_BYTES)
            file.readFully(ciphertext)
            digest.update(record)
            digest.update(ciphertext)
            val nonce = noncePrefix + u64be(index)
            val aad = chunkAad(index, plainLen)
            val plaintext = try {
                native.decryptChunk(keyHandle, nonce, aad, ciphertext)
            } finally {
                ciphertext.fill(0)
                nonce.fill(0)
                aad.fill(0)
            }
            try {
                require(plaintext.size == plainLen)
                if (index == 0L) {
                    require(plaintext.size >= 44)
                    // Compare the complete canonical RIFF/WAVE header, not only
                    // the signature and data length. This validates RIFF size,
                    // fmt fields, sample rate, byte rate, block alignment, and
                    // data length together before the staged artifact is trusted.
                    val expectedWavHeader = PcmWavHeader.create(sampleRateHz, pcmBytes)
                    try {
                        require(plaintext.copyOfRange(0, expectedWavHeader.size).contentEquals(expectedWavHeader)) {
                            "SQVE V2 plaintext WAV header does not match the finalized capture metadata"
                        }
                    } finally {
                        expectedWavHeader.fill(0)
                    }
                }
            } finally {
                plaintext.fill(0)
            }
            plaintextTotal = Math.addExact(plaintextTotal, plainLen.toLong())
            cursor = Math.addExact(cursor, CHUNK_RECORD_BYTES.toLong() + cipherLen)
            index = Math.addExact(index, 1L)
        }
        require(cursor == footerOffset && index > 0L)
        require(plaintextTotal == expectedPlaintext)
        require(index == ((expectedPlaintext - 1L) / CHUNK_BYTES + 1L))
        file.seek(footerOffset)
        val footer = ByteArray(FOOTER_BYTES)
        file.readFully(footer)
        require(footer.copyOfRange(0, 4).contentEquals("SQVF".toByteArray(Charsets.US_ASCII)))
        require(readU16(footer, 4) == VERSION && readU16(footer, 6) == FOOTER_BYTES)
        require(readU64(footer, 8) == index && readU64(footer, 16) == expectedPlaintext)
        require(MessageDigest.isEqual(digest.digest(), footer.copyOfRange(24, 56)))
        require(file.filePointer == totalFileBytes)
        encodedHeader.fill(0)
        record.fill(0)
        footer.fill(0)
    }

    private fun verifyHeaderMac(encoded: ByteArray) {
        val macAt = encoded.size - HEADER_MAC_BYTES
        require(macAt > 0)
        val dek = native.copyFileKeyForWrapping(keyHandle)
        var prk: ByteArray? = null
        var headerKey: ByteArray? = null
        try {
            require(dek.size == 32)
            prk = hmacSha256(fileSalt, dek)
            headerKey = hmacSha256(prk, HEADER_MAC_INFO + byteArrayOf(1))
            val actual = hmacSha256(headerKey, encoded.copyOfRange(0, macAt))
            require(MessageDigest.isEqual(actual, encoded.copyOfRange(macAt, encoded.size))) {
                "SQVE v2 header MAC verification failed"
            }
            actual.fill(0)
        } finally {
            dek.fill(0)
            prk?.fill(0)
            headerKey?.fill(0)
        }
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
        const val HEADER_MAC_BYTES = 32
        val HEADER_MAC_INFO = "SQREC-SQVE2-HEADER-MAC-v1".toByteArray(Charsets.US_ASCII)
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
private fun hmacSha256(key: ByteArray, message: ByteArray): ByteArray =
    javax.crypto.Mac.getInstance("HmacSHA256").run {
        init(javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"))
        doFinal(message)
    }
private fun readU16(b: ByteArray, at: Int): Int =
    ((b[at].toInt() and 0xff) shl 8) or (b[at + 1].toInt() and 0xff)
private fun readU32(b: ByteArray, at: Int): Long =
    ((b[at].toLong() and 0xff) shl 24) or ((b[at + 1].toLong() and 0xff) shl 16) or
        ((b[at + 2].toLong() and 0xff) shl 8) or (b[at + 3].toLong() and 0xff)
private fun readU64(b: ByteArray, at: Int): Long =
    ByteArray(8) { b[at + it] }.fold(0L) { acc, byte -> (acc shl 8) or (byte.toLong() and 0xff) }
private fun readLeU32(b: ByteArray, at: Int): Long =
    (b[at].toLong() and 0xff) or ((b[at + 1].toLong() and 0xff) shl 8) or
        ((b[at + 2].toLong() and 0xff) shl 16) or ((b[at + 3].toLong() and 0xff) shl 24)

