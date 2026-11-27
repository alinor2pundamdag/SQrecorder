package com.alinor.sqrecorder.vault.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class NativeVaultBridgeDeviceTest {
    @Test
    fun opaqueNativeKeyAndChunkAeadRoundTripOnDevice() {
        val bridge = JniVaultNativeKeyBridge()
        val handle = bridge.generateFileKeyHandle()
        val expected = "B4-native-bridge-device-check".toByteArray(Charsets.UTF_8)
        val nonce = ByteArray(12) { it.toByte() }
        val aad = "session=verified;chunk=0".toByteArray(Charsets.UTF_8)
        try {
            val wrapCopy = bridge.copyFileKeyForWrapping(handle)
            assertEquals(32, wrapCopy.size)
            wrapCopy.fill(0)

            val input = expected.copyOf()
            val ciphertextAndTag = bridge.encryptChunk(handle, nonce, aad, input)
            input.fill(0)
            assertEquals(expected.size + 16, ciphertextAndTag.size)
            assertNotEquals(expected.toList(), ciphertextAndTag.toList())

            val plaintext = bridge.decryptChunk(handle, nonce, aad, ciphertextAndTag)
            assertArrayEquals(expected, plaintext)
            plaintext.fill(0)

            val tampered = ciphertextAndTag.copyOf()
            tampered[tampered.lastIndex] = (tampered[tampered.lastIndex].toInt() xor 1).toByte()
            try {
                bridge.decryptChunk(handle, nonce, aad, tampered)
                fail("tampered GCM tag must be rejected")
            } catch (_: IllegalStateException) {
                // JNI maps native authentication failure to a closed error.
            } finally {
                tampered.fill(0)
            }
            ciphertextAndTag.fill(0)
            expected.fill(0)
        } finally {
            bridge.destroyFileKeyHandle(handle)
        }
    }

    @Test
    fun androidKeystoreFailsClosedForLockedSqveV1OaepLabel() {
        val bridge = JniVaultNativeKeyBridge()
        val access = AndroidVaultKeyAccess(bridge, VaultAuthContextVerifier { true })
        try {
            access.currentPublicWrappingKeyId()
            fail("SQVE v1 non-empty OAEP label is not Android Keystore compatible")
        } catch (failure: VaultKeyAccessException) {
            assertEquals(VaultKeyAccessFailure.UNSUPPORTED_PLATFORM, failure.failure)
        }
    }
}
