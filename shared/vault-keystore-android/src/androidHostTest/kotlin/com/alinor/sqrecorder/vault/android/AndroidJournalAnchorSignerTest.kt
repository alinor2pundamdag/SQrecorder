package com.alinor.sqrecorder.vault.android

import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class AndroidJournalAnchorSignerTest {
    @Test
    fun anchorPreimageBindsSequenceAndAuthenticationEpoch() {
        val digest = "ab".repeat(32)
        val original = journalAnchorSigningPayload(4, digest, "key-id", 2, 99)
        val changedSequence = journalAnchorSigningPayload(5, digest, "key-id", 2, 99)
        val changedEpoch = journalAnchorSigningPayload(4, digest, "key-id", 3, 99)

        assertNotEquals(original.toList(), changedSequence.toList())
        assertNotEquals(original.toList(), changedEpoch.toList())
        val domain = "SQREC-JOURNAL-ANCHOR-V1".toByteArray(Charsets.US_ASCII)
        assertContentEquals(domain, original.copyOfRange(0, domain.size))
    }

    @Test
    fun p256AnchorSignatureVerifiesAndRejectsAlteredMetadata() {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"))
        val pair = generator.generateKeyPair()
        val payload = journalAnchorSigningPayload(1, "cd".repeat(32), "key-id", 0, 10)

        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(pair.private)
        signer.update(payload)
        val signatureBytes = signer.sign()

        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(pair.public)
        verifier.update(payload)
        assertTrue(verifier.verify(signatureBytes))

        verifier.initVerify(pair.public)
        verifier.update(journalAnchorSigningPayload(2, "cd".repeat(32), "key-id", 0, 10))
        assertFalse(verifier.verify(signatureBytes))
    }

    @Test
    fun signingKeyIdUsesStablePublicKeyFingerprint() {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"))
        val publicDer = generator.generateKeyPair().public.encoded
        val id = signingKeyId(publicDer)

        check(id.matches(Regex("ecdsa-p256-sha256-v1-[0-9a-f]{32}")))
    }
}
