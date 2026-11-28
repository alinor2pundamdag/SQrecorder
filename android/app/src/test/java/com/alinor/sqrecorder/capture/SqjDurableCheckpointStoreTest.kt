package com.alinor.sqrecorder.capture

import com.alinor.sqrecorder.domain.JournalSignatureAnchor
import com.alinor.sqrecorder.domain.JournalAnchorSigner
import com.alinor.sqrecorder.domain.VaultAuthContext
import com.alinor.sqrecorder.domain.VaultAuthSessionId
import com.alinor.sqrecorder.vault.android.AndroidJournalAnchorVerifier
import com.alinor.sqrecorder.vault.android.JournalAnchorPublicKeyResolver
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.io.File
import java.util.UUID
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SqjDurableCheckpointStoreTest {
    @Test
    fun persistsCanonicalSqacOnlyWhenAnchorMatchesFullyVerifiedJournalHead() {
        val root = createTempDir(prefix = "sqrec-sqac-")
        val session = UUID.randomUUID()
        val journalFile = File(root, "session-$session.sqj")
        val checkpointDirectory = File(root, "checkpoints")
        try {
            CaptureSessionJournal.create(journalFile, session).use { journal ->
                journal.append(CaptureSessionJournal.RECORD_SESSION_CREATED, 100L)
            }
            val digest = journalFile.readBytes().takeLast(32).toByteArray()
                .joinToString("") { "%02x".format(it) }
            val anchor = fixture(sequence = 1L, digestHex = digest)
            val store = SqjDurableCheckpointStore()

            val checkpoint = store.persistAfterJournalSync(journalFile, checkpointDirectory, anchor)
            val bytes = checkpoint.readBytes()
            assertEquals("SQAC", bytes.copyOfRange(0, 4).toString(Charsets.US_ASCII))
            assertEquals(1, java.nio.ByteBuffer.wrap(bytes, 4, 2)
                .order(java.nio.ByteOrder.LITTLE_ENDIAN).short.toInt())
            assertTrue(bytes.size > 68)
            assertEquals(checkpoint, store.persistAfterJournalSync(journalFile, checkpointDirectory, anchor))
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun rejectsStaleSequenceOrDigestBeforeWritingCheckpoint() {
        val root = createTempDir(prefix = "sqrec-sqac-stale-")
        val session = UUID.randomUUID()
        val journalFile = File(root, "session-$session.sqj")
        try {
            CaptureSessionJournal.create(journalFile, session).use { journal ->
                journal.append(CaptureSessionJournal.RECORD_SESSION_CREATED, 100L)
            }
            val digest = journalFile.readBytes().takeLast(32).toByteArray()
                .joinToString("") { "%02x".format(it) }
            val stale = fixture(sequence = 2L, digestHex = digest)
            var rejected = false
            try {
                SqjDurableCheckpointStore().persistAfterJournalSync(journalFile, File(root, "cp"), stale)
            } catch (_: IllegalStateException) {
                rejected = true
            }
            assertTrue(rejected)
            assertFalse(File(root, "cp").exists())
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun conflictingSameSequenceCheckpointIsNeverOverwritten() {
        val root = createTempDir(prefix = "sqrec-sqac-conflict-")
        val session = UUID.randomUUID()
        val journalFile = File(root, "session-$session.sqj")
        val cpDir = File(root, "cp")
        try {
            CaptureSessionJournal.create(journalFile, session).use { journal ->
                journal.append(CaptureSessionJournal.RECORD_SESSION_CREATED, 100L)
            }
            val digest = journalFile.readBytes().takeLast(32).toByteArray()
                .joinToString("") { "%02x".format(it) }
            val store = SqjDurableCheckpointStore()
            val original = store.persistAfterJournalSync(journalFile, cpDir, fixture(1L, digest)).readBytes()
            var rejected = false
            try {
                store.persistAfterJournalSync(journalFile, cpDir, fixture(1L, digest, monotonicNs = 222L))
            } catch (_: IllegalStateException) {
                rejected = true
            }
            assertTrue(rejected)
            assertEquals(original.toList(), cpDir.listFiles()!!.single().readBytes().toList())
        } finally {
            root.deleteRecursively()
        }
    }


    @Test
    fun persistedCheckpointSignatureVerifiesAndBecomesStaleAfterJournalAdvance() {
        val root = createTempDir(prefix = "sqrec-sqac-verify-")
        val session = UUID.randomUUID()
        val journalFile = File(root, "session-$session.sqj")
        val cpDir = File(root, "cp")
        try {
            CaptureSessionJournal.create(journalFile, session).use { journal ->
                journal.append(CaptureSessionJournal.RECORD_SESSION_CREATED, 100L)
            }
            val journalBytes = journalFile.readBytes()
            val digest = journalBytes.takeLast(32).toByteArray()
            val digestHex = digest.joinToString("") { "%02x".format(it) }
            val pair = KeyPairGenerator.getInstance("EC").apply {
                initialize(java.security.spec.ECGenParameterSpec("secp256r1"))
            }.generateKeyPair()
            val fingerprint = MessageDigest.getInstance("SHA-256").digest(pair.public.encoded)
                .take(16).joinToString("") { "%02x".format(it) }
            val keyId = "ecdsa-p256-sha256-v1-$fingerprint"
            val epoch = 4L
            val timestamp = 1234L
            val preimage = ByteArrayOutputStream().apply {
                write("SQREC-JOURNAL-ANCHOR-V1".toByteArray(Charsets.US_ASCII))
                write(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(1L).array())
                write(digest)
                write(ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN).putShort(keyId.length.toShort()).array())
                write(keyId.toByteArray(Charsets.UTF_8))
                write(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(epoch).array())
                write(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(timestamp).array())
            }.toByteArray()
            val signer = Signature.getInstance("SHA256withECDSA").apply {
                initSign(pair.private)
                update(preimage)
            }
            val anchor = JournalSignatureAnchor(
                formatVersion = 1,
                sequence = 1L,
                digestHex = digestHex,
                signatureAlgorithmId = "ecdsa-p256-sha256-v1",
                signingKeyId = keyId,
                signatureBase64 = java.util.Base64.getEncoder().encodeToString(signer.sign()),
                authenticationEpoch = epoch,
                monotonicTimestampNs = timestamp,
            )
            val store = SqjDurableCheckpointStore()
            val verifier = AndroidJournalAnchorVerifier(
                JournalAnchorPublicKeyResolver { requested -> if (requested == keyId) pair.public.encoded else null },
            )
            val coordinator = SqjAuthenticatedCheckpointCoordinator(
                object : JournalAnchorSigner {
                    override fun signCommittedDigest(
                        sequence: Long,
                        digestHex: String,
                        authContext: VaultAuthContext,
                    ): JournalSignatureAnchor {
                        assertEquals(anchor.sequence, sequence)
                        assertEquals(anchor.digestHex, digestHex)
                        return anchor
                    }
                },
                verifier,
                store,
            )
            val authContext = VaultAuthContext(
                sessionId = VaultAuthSessionId("host-test-session"),
                authorizationEpoch = epoch,
                expiresAtMonotonicNs = Long.MAX_VALUE,
            )
            val cp = coordinator.anchorDurableHead(journalFile, cpDir, authContext)
            assertEquals(SqacVerificationResult.VALID, store.verifyPersisted(journalFile, cp, verifier))

            // A separately valid journal with a later terminal sequence must
            // not accept this checkpoint as its current-head proof.
            val advancedFile = File(root, "advanced.sqj")
            val advancedId = UUID.randomUUID()
            CaptureSessionJournal.create(advancedFile, advancedId).use { journal ->
                journal.append(CaptureSessionJournal.RECORD_SESSION_CREATED, 100L)
                journal.append(CaptureSessionJournal.RECORD_CAPTURE_STARTED, 200L)
            }
            assertEquals(SqacVerificationResult.SEQUENCE_MISMATCH, store.verifyPersisted(advancedFile, cp, verifier))
            preimage.fill(0)
            digest.fill(0)
            journalBytes.fill(0)
        } finally {
            root.deleteRecursively()
        }
    }

    private fun fixture(
        sequence: Long,
        digestHex: String,
        monotonicNs: Long = 123L,
    ) = JournalSignatureAnchor(
        formatVersion = 1,
        sequence = sequence,
        digestHex = digestHex,
        signatureAlgorithmId = "ecdsa-p256-sha256-v1",
        signingKeyId = "ecdsa-p256-sha256-v1-0123456789abcdef0123456789abcdef",
        signatureBase64 = "MAYCAQECAQE=",
        authenticationEpoch = 1L,
        monotonicTimestampNs = monotonicNs,
    )
}
