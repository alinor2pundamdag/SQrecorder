package com.alinor.sqrecorder.vault.android

import android.util.Base64
import com.alinor.sqrecorder.domain.VaultFileKeyHandle
import com.alinor.sqrecorder.domain.VaultV2RecipientWrap
import com.alinor.sqrecorder.domain.VaultV2WrapSuite
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertContentEquals

class AndroidSqveV2HeaderCodecTest {
    @Test
    fun streamingHeaderMatchesIndependentCanonicalV2Vector() {
        val fake = FixedDekBridge()
        val der = ByteArray(91) { 0x30 }
        val wrapNonce = ByteArray(12) { 0x77 }
        val ciphertextAndTag = ByteArray(48) { 0x77 }
        val payload = byteArrayOf(0, der.size.toByte()) + der + wrapNonce + ciphertextAndTag
        val recipient = VaultV2RecipientWrap(
            suite = VaultV2WrapSuite.ECDH_P256_HKDF_SHA256_AES256_GCM,
            recipientKeyId = "device:primary",
            wrappedDekBase64 = Base64.encodeToString(payload, Base64.NO_WRAP),
            ephemeralPublicKeyBase64 = Base64.encodeToString(der, Base64.NO_WRAP),
            wrapNonceHex = wrapNonce.joinToString("") { "%02x".format(it.toInt() and 0xff) },
        )
        val header = AndroidSqveV2HeaderCodec(fake).serializeStreamingHeader(
            keyHandle = VaultFileKeyHandle("9"),
            fileId = ByteArray(16) { 0x11 },
            fileSalt = ByteArray(32) { 0x22 },
            noncePrefix = byteArrayOf(1, 2, 3, 4),
            recipient = recipient,
        )
        assertContentEquals(
            byteArrayOf(
                0xf9.toByte(), 0x16, 0xcb.toByte(), 0x13, 0xbe.toByte(), 0x1c, 0x60, 0x7a,
                0x17, 0xdf.toByte(), 0x7a, 0xc7.toByte(), 0xd5.toByte(), 0x72, 0x6c, 0xcb.toByte(),
                0x58, 0x0d, 0xba.toByte(), 0x8e.toByte(), 0x40, 0x6c, 0x10, 0xc5.toByte(),
                0xef.toByte(), 0xa2.toByte(), 0xd2.toByte(), 0x4e, 0x32, 0x88.toByte(), 0xfd.toByte(), 0xe9.toByte(),
            ),
            MessageDigest.getInstance("SHA-256").digest(header),
        )
    }
}

private class FixedDekBridge : VaultNativeKeyBridge {
    override fun generateFileKeyHandle() = VaultFileKeyHandle("9")
    override fun destroyFileKeyHandle(handle: VaultFileKeyHandle) = Unit
    override fun copyFileKeyForWrapping(handle: VaultFileKeyHandle) = ByteArray(32) { 0x55 }
    override fun importUnwrappedFileKey(dek: ByteArray) = VaultFileKeyHandle("10")
    override fun encryptChunk(
        handle: VaultFileKeyHandle, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray,
    ) = ByteArray(plaintext.size + 16)
    override fun decryptChunk(
        handle: VaultFileKeyHandle, nonce: ByteArray, aad: ByteArray, ciphertextAndTag: ByteArray,
    ) = ByteArray(ciphertextAndTag.size - 16)
}
