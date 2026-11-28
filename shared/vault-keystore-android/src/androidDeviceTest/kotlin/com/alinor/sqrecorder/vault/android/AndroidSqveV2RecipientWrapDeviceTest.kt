package com.alinor.sqrecorder.vault.android

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.alinor.sqrecorder.domain.VaultV2WrapSuite
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AndroidSqveV2RecipientWrapDeviceTest {
    @Test
    fun platformSelectsExplicitV2SuiteAndWrapsARealNativeDek() {
        val native = JniVaultNativeKeyBridge()
        val access = AndroidSqveV2KeyAccess(native, VaultAuthContextVerifier { false })
        val handle = access.createRandomV2FileKeyHandle()
        val fileId = ByteArray(16).also(java.security.SecureRandom()::nextBytes)
        val salt = ByteArray(32).also(java.security.SecureRandom()::nextBytes)
        try {
            val recipientId = access.currentPublicV2RecipientKeyId()
            val wrap = access.wrapFileKeyForV2(handle, recipientId, fileId, salt)
            assertEquals(recipientId, wrap.recipientKeyId)
            if (Build.VERSION.SDK_INT < 31) {
                assertEquals(
                    VaultV2WrapSuite.RSA3072_OAEP_SHA256_MGF1_SHA1_EMPTY_LABEL,
                    wrap.suite,
                )
                assertEquals(512, wrap.wrappedDekBase64.length)
                assertNull(wrap.ephemeralPublicKeyBase64)
                assertNull(wrap.wrapNonceHex)
            } else {
                assertEquals(VaultV2WrapSuite.ECDH_P256_HKDF_SHA256_AES256_GCM, wrap.suite)
                assertNotNull(wrap.ephemeralPublicKeyBase64)
                assertNotNull(wrap.wrapNonceHex)
                assertTrueCanonicalEcdhPayload(wrap.wrappedDekBase64)
            }
        } finally {
            fileId.fill(0)
            salt.fill(0)
            native.destroyFileKeyHandle(handle)
        }
    }

    private fun assertTrueCanonicalEcdhPayload(encoded: String) {
        val bytes = SqveBase64.decodeCanonical(encoded)
        try {
            assertEquals(2 + 91 + 12 + 48, bytes.size) // P-256 SPKI is DER encoded by the platform provider
        } finally {
            bytes.fill(0)
        }
    }
}
