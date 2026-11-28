package com.alinor.sqrecorder.capture

import java.io.File
import com.alinor.sqrecorder.domain.VaultFileKeyHandle
import com.alinor.sqrecorder.domain.VaultV2RecipientWrap
import com.alinor.sqrecorder.domain.VaultV2WrapSuite
import com.alinor.sqrecorder.vault.android.AndroidSqveV2HeaderCodec
import com.alinor.sqrecorder.vault.android.VaultNativeKeyBridge
import java.io.RandomAccessFile
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SqveV2EncryptedWavSinkTest {
    @Test
    fun captureSinkWritesOnlyAuthenticatedEncryptedWavChunks() {
        val native = TestChunkBridge()
        val handle = VaultFileKeyHandle("test")
        val fileId = ByteArray(16) { 0x11 }
        val salt = ByteArray(32) { 0x22 }
        val noncePrefix = byteArrayOf(1, 2, 3, 4)
        val ephemeral = ByteArray(91) { 0x30 }
        val wrapNonce = ByteArray(12) { 0x77 }
        val wrapBytes = byteArrayOf(0, ephemeral.size.toByte()) + ephemeral + wrapNonce + ByteArray(48) { 0x77 }
        val wrap = VaultV2RecipientWrap(
            suite = VaultV2WrapSuite.ECDH_P256_HKDF_SHA256_AES256_GCM,
            recipientKeyId = "android-v2-ecdh-" + "a".repeat(64),
            wrappedDekBase64 = java.util.Base64.getEncoder().encodeToString(wrapBytes),
            ephemeralPublicKeyBase64 = java.util.Base64.getEncoder().encodeToString(ephemeral),
            wrapNonceHex = wrapNonce.joinToString("") { "%02x".format(it.toInt() and 0xff) },
        )
        val header = AndroidSqveV2HeaderCodec(native).serializeStreamingHeader(
            handle, fileId, salt, noncePrefix, wrap,
        )
        val output = File.createTempFile("sqve-v2-sink", ".part")
        try {
            val sink = SqveV2EncryptedWavSink(
                RandomAccessFile(output, "rw"), native, handle,
                fileId, salt, noncePrefix, header, 48_000,
            )
            val pcm = ByteArray(2 * 1_048_576 + 19) { 0x5a }
            sink.writePcm(pcm, 0, pcm.size)
            val envelopeBytes = sink.finish(pcm.size.toLong())
            sink.verifyFinished(pcm.size.toLong())
            pcm.fill(0)

            // The same verification gate must reject footer tampering before
            // any caller can promote this staged file.
            RandomAccessFile(output, "rw").use { tamper ->
                val at = tamper.length() - 1L
                tamper.seek(at)
                val original = tamper.readByte()
                tamper.seek(at)
                tamper.writeByte(original.toInt() xor 0x01)
                var rejected = false
                try {
                    sink.verifyFinished(2 * 1_048_576L + 19L)
                } catch (_: IllegalArgumentException) {
                    rejected = true
                } finally {
                    tamper.seek(at)
                    tamper.writeByte(original.toInt())
                    tamper.fd.sync()
                }
                assertTrue("tampered footer digest must fail verification", rejected)
            }
            sink.close()

            val encoded = output.readBytes()
            assertEquals(envelopeBytes, encoded.size.toLong())
            assertArrayEquals(byteArrayOf(0x53, 0x51, 0x56, 0x45), encoded.copyOfRange(0, 4))
            assertTrue(encoded.indexOfSubsequence("RIFF".toByteArray(Charsets.US_ASCII)) < 0)
            val headerLength = readU32(encoded, 6).toInt()
            assertEquals(header.size, headerLength)
            val chunk0At = headerLength
            assertArrayEquals("SQVC".toByteArray(Charsets.US_ASCII), encoded.copyOfRange(chunk0At, chunk0At + 4))
            val plain0Length = readU32(encoded, chunk0At + 12).toInt()
            assertEquals(1_048_576, plain0Length)
            val encrypted0At = chunk0At + 20
            val nonce0 = noncePrefix + u64be(0)
            val aad0 = chunkAad(fileId, salt, noncePrefix, 0, plain0Length)
            val plain0 = native.decrypt(handle, nonce0, aad0, encoded.copyOfRange(encrypted0At, encrypted0At + plain0Length + 16))
            assertArrayEquals("RIFF".toByteArray(Charsets.US_ASCII), plain0.copyOfRange(0, 4))
            assertEquals(pcm.size, readLeU32(plain0, 40).toInt())
            plain0.fill(0)

            val chunk1At = encrypted0At + plain0Length + 16
            assertArrayEquals("SQVC".toByteArray(Charsets.US_ASCII), encoded.copyOfRange(chunk1At, chunk1At + 4))
            assertEquals(1_048_576, readU32(encoded, chunk1At + 12).toInt())
            assertEquals(1L, readU64(encoded, chunk1At + 4))
            val chunk2At = chunk1At + 20 + 1_048_576 + 16
            assertArrayEquals("SQVC".toByteArray(Charsets.US_ASCII), encoded.copyOfRange(chunk2At, chunk2At + 4))
            assertEquals(63, readU32(encoded, chunk2At + 12).toInt())
            assertEquals(2L, readU64(encoded, chunk2At + 4))
            val footerAt = encoded.size - 56
            assertArrayEquals("SQVF".toByteArray(Charsets.US_ASCII), encoded.copyOfRange(footerAt, footerAt + 4))
            assertEquals(3L, readU64(encoded, footerAt + 8))
            assertEquals(pcm.size.toLong() + 44L, readU64(encoded, footerAt + 16))
            assertArrayEquals(
                MessageDigest.getInstance("SHA-256").digest(encoded.copyOfRange(0, footerAt)),
                encoded.copyOfRange(footerAt + 24, encoded.size),
            )
        } finally {
            output.delete()
            header.fill(0)
            fileId.fill(0); salt.fill(0); noncePrefix.fill(0)
        }
    }
}

private class TestChunkBridge : VaultNativeKeyBridge {
    private val dek = ByteArray(32) { 0x55 }
    override fun generateFileKeyHandle() = VaultFileKeyHandle("test")
    override fun destroyFileKeyHandle(handle: VaultFileKeyHandle) = Unit
    override fun copyFileKeyForWrapping(handle: VaultFileKeyHandle) = dek.copyOf()
    override fun importUnwrappedFileKey(dek: ByteArray) = VaultFileKeyHandle("imported")
    override fun encryptChunk(
        handle: VaultFileKeyHandle, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray,
    ): ByteArray = Cipher.getInstance("AES/GCM/NoPadding").run {
        init(Cipher.ENCRYPT_MODE, SecretKeySpec(dek, "AES"), GCMParameterSpec(128, nonce))
        updateAAD(aad)
        doFinal(plaintext)
    }
    override fun decryptChunk(
        handle: VaultFileKeyHandle, nonce: ByteArray, aad: ByteArray, ciphertextAndTag: ByteArray,
    ): ByteArray = decrypt(handle, nonce, aad, ciphertextAndTag)
    fun decrypt(
        handle: VaultFileKeyHandle, nonce: ByteArray, aad: ByteArray, ciphertextAndTag: ByteArray,
    ): ByteArray = Cipher.getInstance("AES/GCM/NoPadding").run {
        init(Cipher.DECRYPT_MODE, SecretKeySpec(dek, "AES"), GCMParameterSpec(128, nonce))
        updateAAD(aad)
        doFinal(ciphertextAndTag)
    }
}

private fun chunkAad(
    fileId: ByteArray, salt: ByteArray, prefix: ByteArray, index: Long, length: Int,
): ByteArray = "SQREC-SQVE2-CHUNK-AAD-v1".toByteArray(Charsets.US_ASCII) +
    u16be(2) + u16be(1) + fileId + salt + prefix + u32be(1_048_576) +
    u64be(-1L) + u64be(index) + u32be(length)

private fun u16be(v: Int) = byteArrayOf((v ushr 8).toByte(), v.toByte())
private fun u32be(v: Int) = byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())
private fun u64be(v: Long) = ByteArray(8) { (v ushr (56 - it * 8)).toByte() }
private fun readLeU32(b: ByteArray, at: Int): Long =
    (b[at].toLong() and 0xff) or ((b[at + 1].toLong() and 0xff) shl 8) or
        ((b[at + 2].toLong() and 0xff) shl 16) or ((b[at + 3].toLong() and 0xff) shl 24)
private fun readU32(b: ByteArray, at: Int): Long =
    ((b[at].toLong() and 0xff) shl 24) or ((b[at + 1].toLong() and 0xff) shl 16) or
        ((b[at + 2].toLong() and 0xff) shl 8) or (b[at + 3].toLong() and 0xff)
private fun readU64(b: ByteArray, at: Int): Long =
    ByteArray(8) { b[at + it] }.fold(0L) { acc, byte -> (acc shl 8) or (byte.toLong() and 0xff) }
private fun ByteArray.indexOfSubsequence(needle: ByteArray): Int =
    indices.firstOrNull { start -> start + needle.size <= size && needle.indices.all { this[start + it] == needle[it] } } ?: -1
