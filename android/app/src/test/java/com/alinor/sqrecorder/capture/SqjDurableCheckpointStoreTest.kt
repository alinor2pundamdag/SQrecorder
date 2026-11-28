package com.alinor.sqrecorder.capture

import com.alinor.sqrecorder.domain.JournalSignatureAnchor
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
