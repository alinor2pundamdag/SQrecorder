package com.alinor.sqrecorder.vault.android

import com.alinor.sqrecorder.domain.VaultAuthContext
import com.alinor.sqrecorder.domain.VaultAuthSessionId
import java.security.KeyPairGenerator
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class AndroidVaultKeyAccessTest {
    @Test
    fun publicWrappingKeyIdIsDeterministicAndNonSecret() {
        val generator = KeyPairGenerator.getInstance("RSA")
        generator.initialize(2048)
        val publicKey = generator.generateKeyPair().public

        val first = vaultWrappingKeyId(publicKey)
        val second = vaultWrappingKeyId(publicKey)

        assertEquals(first, second)
        assertEquals(32, first.substringAfterLast('-').length)
        assertTrue(first.matches(Regex("rsa-oaep-sha256-v1-[0-9a-f]{32}")))
    }

    @Test
    fun authContextMustBeCurrentAndWithinThirtySecondWindow() {
        val now = 5_000_000_000L
        val context = VaultAuthContext(
            sessionId = VaultAuthSessionId("host-test-session"),
            authorizationEpoch = 7,
            expiresAtMonotonicNs = now + VAULT_AUTH_WINDOW_NANOS,
        )
        val current = VaultAuthContextVerifier { it.authorizationEpoch == 7L }

        assertTrue(isCurrentVaultAuthContext(context, now, current))
        assertEquals(
            false,
            isCurrentVaultAuthContext(
                context.copy(expiresAtMonotonicNs = now + VAULT_AUTH_WINDOW_NANOS + 1),
                now,
                current,
            ),
        )
        assertEquals(false, isCurrentVaultAuthContext(context, now, VaultAuthContextVerifier { false }))
        // Expiry is an absolute monotonic deadline: one nanosecond after issuance\n        // remains valid; exactly at the deadline it must be rejected.\n        assertTrue(isCurrentVaultAuthContext(context, now + 1, current))\n        assertEquals(\n            false,\n            isCurrentVaultAuthContext(\n                context.copy(expiresAtMonotonicNs = now + 1),\n                now + 1,\n                current,\n            ),\n        )
    }

    @Test
    fun lockedSqveV1LabelIsExplicitlyRejectedByAndroidKeystoreGate() {
        assertEquals(false, androidKeystoreSupportsSqveV1Oaep(35))
        assertEquals(false, androidKeystoreSupportsSqveV1Oaep(36))
    }

    @Test
    fun oaepContractPinsSha256ForDigestAndMgfAndUsesEnvelopeLabel() {
        val parameters = vaultOaepParameters()
        assertEquals("SHA-256", parameters.digestAlgorithm)
        assertEquals("MGF1", parameters.mgfAlgorithm)
        assertEquals(
            MGF1ParameterSpec.SHA256.digestAlgorithm,
            (parameters.mgfParameters as MGF1ParameterSpec).digestAlgorithm,
        )
        assertContentEquals(
            "SQREC-VAULT-DEK-v1".toByteArray(Charsets.UTF_8),
            (parameters.pSource as PSource.PSpecified).value,
        )
    }

    @Test
    fun oaepWrapRoundTripUsesExactLabelAndMgfDigest() {
        val generator = KeyPairGenerator.getInstance("RSA")
        generator.initialize(2048)
        val pair = generator.generateKeyPair()
        val dek = ByteArray(32) { (it * 7).toByte() }

        val encrypt = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        encrypt.init(Cipher.ENCRYPT_MODE, pair.public, vaultOaepParameters())
        val wrapped = encrypt.doFinal(dek)

        val decrypt = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        decrypt.init(Cipher.DECRYPT_MODE, pair.private, vaultOaepParameters())
        assertContentEquals(dek, decrypt.doFinal(wrapped))

        val wrongLabel = OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            PSource.PSpecified("wrong-label".toByteArray(Charsets.UTF_8)),
        )
        decrypt.init(Cipher.DECRYPT_MODE, pair.private, wrongLabel)
        kotlin.test.assertFails { decrypt.doFinal(wrapped) }
    }
}
