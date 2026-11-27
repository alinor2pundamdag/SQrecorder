package com.alinor.sqrecorder.vault.android

import com.alinor.sqrecorder.domain.JournalSignatureAnchor
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import kotlin.test.Test
import kotlin.test.assertEquals

class AndroidJournalAnchorVerifierTest {
    @Test
    fun verifiesAnchorAndRejectsAlteredSequenceAndUnknownKey() {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"))
        val pair = generator.generateKeyPair()
        val keyId = publicKeyId(pair.public.encoded)
        val digest = "ef".repeat(32)
        val payload = journalAnchorSigningPayload(9, digest, keyId, 3, 1234)
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(pair.private)
        signer.update(payload)
        val anchor = JournalSignatureAnchor(
            formatVersion = 1,
            sequence = 9,
            digestHex = digest,
            signatureAlgorithmId = "ecdsa-p256-sha256-v1",
            signingKeyId = keyId,
            signatureBase64 = java.util.Base64.getEncoder().encodeToString(signer.sign()),
            authenticationEpoch = 3,
            monotonicTimestampNs = 1234,
        )
        val verifier = AndroidJournalAnchorVerifier(
            JournalAnchorPublicKeyResolver { id -> if (id == keyId) pair.public.encoded else null },
        )
        assertEquals(JournalAnchorVerificationResult.VALID, verifier.verify(anchor))
        assertEquals(
            JournalAnchorVerificationResult.INVALID_SIGNATURE,
            verifier.verify(anchor.copy(sequence = 10)),
        )
        assertEquals(
            JournalAnchorVerificationResult.KEY_NOT_FOUND,
            AndroidJournalAnchorVerifier(JournalAnchorPublicKeyResolver { null }).verify(anchor),
        )
    }

    @Test
    fun rejectsResolverReturningKeyUnderWrongFingerprint() {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"))
        val pair = generator.generateKeyPair()
        val anchor = JournalSignatureAnchor(
            1, 1, "01".repeat(32), "ecdsa-p256-sha256-v1",
            "ecdsa-p256-sha256-v1-00000000000000000000000000000000",
            java.util.Base64.getEncoder().encodeToString(ByteArray(8)), 0, 0,
        )
        assertEquals(
            JournalAnchorVerificationResult.KEY_ID_MISMATCH,
            AndroidJournalAnchorVerifier(JournalAnchorPublicKeyResolver { pair.public.encoded })
                .verify(anchor),
        )
    }
}
