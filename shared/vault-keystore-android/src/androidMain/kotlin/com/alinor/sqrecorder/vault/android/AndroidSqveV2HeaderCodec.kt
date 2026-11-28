package com.alinor.sqrecorder.vault.android

import com.alinor.sqrecorder.domain.VaultFileKeyHandle
import com.alinor.sqrecorder.domain.VaultV2RecipientWrap
import com.alinor.sqrecorder.domain.VaultV2WrapSuite
import java.io.ByteArrayOutputStream
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Android-side canonical SQVE v2 header serializer. The Rust core independently
 * parses and authenticates these bytes; this implementation exists to create
 * the capture header before the streaming native chunk sink starts.
 */
public class AndroidSqveV2HeaderCodec(
    private val native: VaultNativeKeyBridge,
) {
    public fun serializeStreamingHeader(
        keyHandle: VaultFileKeyHandle,
        fileId: ByteArray,
        fileSalt: ByteArray,
        noncePrefix: ByteArray,
        recipient: VaultV2RecipientWrap,
    ): ByteArray {
        require(fileId.size == 16 && fileSalt.size == 32 && noncePrefix.size == 4)
        require(recipient.recipientKeyId.isCanonicalV2Id())
        val id = recipient.recipientKeyId.toByteArray(Charsets.US_ASCII)
        val suite = when (recipient.suite) {
            VaultV2WrapSuite.RSA_OAEP_SHA256_MGF1_SHA256_EMPTY_LABEL -> RSA_WRAP_SUITE
            VaultV2WrapSuite.ECDH_P256_HKDF_SHA256_AES256_GCM -> ECDH_WRAP_SUITE
            VaultV2WrapSuite.RSA3072_OAEP_SHA256_MGF1_SHA1_EMPTY_LABEL -> RSA3072_SHA1_WRAP_SUITE
        }
        val wrapped = try {
            SqveBase64.decodeCanonical(recipient.wrappedDekBase64)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("V2 wrapped-DEK payload is not canonical Base64", e)
        }
        if (SqveBase64.encodeNoWrap(wrapped) != recipient.wrappedDekBase64 ||
            wrapped.isEmpty() || wrapped.size > MAX_WRAPPED_BYTES
        ) {
            wrapped.fill(0)
            throw IllegalArgumentException("V2 wrapped-DEK payload violates wire bounds")
        }
        if (suite == ECDH_WRAP_SUITE) validateEcdhPayload(wrapped)

        val body = ByteArrayOutputStream()
        body.write(MAGIC)
        body.write(u16be(VERSION))
        body.write(byteArrayOf(0, 0, 0, 0)) // total header length patched below
        body.write(u16be(CONTENT_SUITE_AES_GCM))
        body.write(u16be(FLAG_STREAMING))
        body.write(fileId)
        body.write(fileSalt)
        body.write(noncePrefix)
        body.write(u32be(CHUNK_BYTES))
        body.write(u64be(-1L)) // authenticated unknown-length sentinel
        body.write(u64be(-1L)) // authenticated unknown-count sentinel
        body.write(u16be(1)) // exactly one recipient for this Android provider
        body.write(u16be(0)) // reserved
        body.write(u16be(suite))
        body.write(u16be(id.size))
        body.write(u32be(wrapped.size))
        body.write(id)
        body.write(wrapped)
        wrapped.fill(0)

        val authenticated = body.toByteArray()
        val headerLength = authenticated.size + HEADER_MAC_BYTES
        require(headerLength <= MAX_HEADER_BYTES)
        authenticated[6] = (headerLength ushr 24).toByte()
        authenticated[7] = (headerLength ushr 16).toByte()
        authenticated[8] = (headerLength ushr 8).toByte()
        authenticated[9] = headerLength.toByte()

        val dek = native.copyFileKeyForWrapping(keyHandle)
        if (dek.size != DEK_BYTES) {
            dek.fill(0)
            authenticated.fill(0)
            throw IllegalStateException("Native V2 DEK length mismatch")
        }
        var prk: ByteArray? = null
        var headerKey: ByteArray? = null
        try {
            prk = hmacSha256(fileSalt, dek)
            headerKey = hmacSha256(prk, HEADER_MAC_INFO + byteArrayOf(1))
            val mac = hmacSha256(headerKey, authenticated)
            return authenticated + mac
        } finally {
            dek.fill(0)
            prk?.fill(0)
            headerKey?.fill(0)
            authenticated.fill(0)
        }
    }

    private companion object {
        const val VERSION = 2
        const val CONTENT_SUITE_AES_GCM = 1
        const val RSA_WRAP_SUITE = 1
        const val ECDH_WRAP_SUITE = 2
        const val RSA3072_SHA1_WRAP_SUITE = 3
        const val FLAG_STREAMING = 1
        const val CHUNK_BYTES = 1_048_576
        const val DEK_BYTES = 32
        const val HEADER_MAC_BYTES = 32
        const val MAX_HEADER_BYTES = 65_535
        const val MAX_WRAPPED_BYTES = 8_192
        const val MIN_ECDH_PAYLOAD_BYTES = 63
        val MAGIC = byteArrayOf(0x53, 0x51, 0x56, 0x45)
        val HEADER_MAC_INFO = "SQREC-SQVE2-HEADER-MAC-v1".toByteArray(Charsets.US_ASCII)
    }
}

private const val V2_MIN_ECDH_PAYLOAD_BYTES = 63
private const val V2_MAX_WRAPPED_BYTES = 8_192

private fun validateEcdhPayload(payload: ByteArray) {
    if (payload.size !in V2_MIN_ECDH_PAYLOAD_BYTES..V2_MAX_WRAPPED_BYTES) {
        throw IllegalArgumentException("Malformed V2 ECDH wrapped-DEK payload")
    }
    val derLength = ((payload[0].toInt() and 0xff) shl 8) or (payload[1].toInt() and 0xff)
    if (derLength !in 1..2_048 || 2 + derLength + 12 + 48 != payload.size) {
        throw IllegalArgumentException("Malformed V2 ECDH wrapped-DEK framing")
    }
}

private fun hmacSha256(key: ByteArray, message: ByteArray): ByteArray =
    Mac.getInstance("HmacSHA256").run {
        init(SecretKeySpec(key, "HmacSHA256"))
        doFinal(message)
    }

private fun u16be(value: Int): ByteArray =
    byteArrayOf((value ushr 8).toByte(), value.toByte())

private fun u32be(value: Int): ByteArray =
    byteArrayOf((value ushr 24).toByte(), (value ushr 16).toByte(), (value ushr 8).toByte(), value.toByte())

private fun u64be(value: Long): ByteArray =
    ByteArray(8) { index -> (value ushr (56 - index * 8)).toByte() }

private fun String.isCanonicalV2Id(): Boolean =
    isNotEmpty() && length <= 128 && all {
        it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' ||
            it == '.' || it == '_' || it == '-' || it == ':'
    }
