package com.alinor.sqrecorder.capture

import java.io.File
import java.io.RandomAccessFile
import java.util.UUID
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CaptureSessionJournalTest {
    @Test
    fun appendsDurableCanonicalSqjChainAndScannerAcceptsIt() {
        val directory = createTempDir(prefix = "sqrec-sqj-")
        val session = UUID.fromString("12345678-1234-4234-8234-123456789abc")
        val journalFile = File(directory, "session-$session.sqj")
        try {
            CaptureSessionJournal.create(journalFile, session).use { journal ->
                journal.append(CaptureSessionJournal.RECORD_SESSION_CREATED, 100L)
                journal.append(
                    CaptureSessionJournal.RECORD_CAPTURE_STARTED,
                    200L,
                    mapOf("captureEpoch" to 1L, "sampleRateHz" to 48_000L),
                )
                journal.append(
                    CaptureSessionJournal.RECORD_FILE_FINALIZED,
                    300L,
                    mapOf("encryptedBytes" to 1_234L),
                )
            }
            val result = CaptureSessionJournal.scan(journalFile)
            assertTrue(result.valid)
            assertFalse(result.damagedTail)
            assertEquals(3L, result.lastSequence)
            assertTrue(result.finalized)
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun scannerRejectsDamagedDigestWithoutModifyingOriginalJournal() {
        val directory = createTempDir(prefix = "sqrec-sqj-corrupt-")
        val session = UUID.randomUUID()
        val journalFile = File(directory, "session-$session.sqj")
        try {
            CaptureSessionJournal.create(journalFile, session).use { journal ->
                journal.append(CaptureSessionJournal.RECORD_SESSION_CREATED, 100L)
            }
            RandomAccessFile(journalFile, "rw").use { file ->
                file.seek(file.length() - 1L)
                val byte = file.readByte()
                file.seek(file.length() - 1L)
                file.writeByte(byte.toInt() xor 0x01)
                file.fd.sync()
            }
            val before = journalFile.readBytes()
            val result = CaptureSessionJournal.scan(journalFile)
            assertFalse(result.valid)
            assertEquals(before.toList(), journalFile.readBytes().toList())
        } finally {
            directory.deleteRecursively()
        }
    }
}
