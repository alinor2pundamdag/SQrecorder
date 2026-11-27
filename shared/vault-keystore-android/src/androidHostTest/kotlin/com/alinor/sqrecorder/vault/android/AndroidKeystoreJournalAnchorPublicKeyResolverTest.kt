package com.alinor.sqrecorder.vault.android

import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertNull

class AndroidKeystoreJournalAnchorPublicKeyResolverTest {
    private fun p256PublicKey(): ByteArray {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"))
        return generator.generateKeyPair().public.encoded
    }

    @Test
    fun resolvesHistoricalKeyFromRetainedSetAndReturnsDefensiveCopy() {
        val historical = p256PublicKey()
        val current = p256PublicKey()
        val keyId = publicKeyId(historical)
        val resolved = resolveRetainedAnchorPublicKey(keyId, listOf(current, historical))
        assertContentEquals(historical, resolved)
        resolved!![0] = (resolved[0].toInt() xor 0xff).toByte()
        assertContentEquals(
            historical,
            resolveRetainedAnchorPublicKey(keyId, listOf(current, historical)),
        )
    }

    @Test
    fun missingOrMalformedHistoricalKeyNeverFallsBackToCurrentKey() {
        val current = p256PublicKey()
        assertNull(resolveRetainedAnchorPublicKey("ecdsa-p256-sha256-v1-" + "0".repeat(32), listOf(current)))
        assertNull(resolveRetainedAnchorPublicKey("bad-key-id", listOf(current)))
        assertNull(resolveRetainedAnchorPublicKey(publicKeyId(current), listOf(byteArrayOf(1, 2, 3))))
    }
}
