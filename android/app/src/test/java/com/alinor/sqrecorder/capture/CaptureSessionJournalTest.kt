package com.alinor.sqrecorder.capture

import java.io.File
import java.nio.file.Files
import java.io.RandomAccessFile
import java.util.UUID
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CaptureSessionJournalTest {
    @Test
    fun appendsDurableCanonicalSqjChainAndScannerAcceptsIt() {
        val directory = Files.createTempDirectory("sqrec-sqj-").toFile()
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
                journal.append(CaptureSessionJournal.RECORD_CAPTURE_STOP_REQUESTED, 250L)
                journal.append(CaptureSessionJournal.RECORD_CAPTURE_STOPPED, 260L, mapOf("pcmBytes" to 960L))
                journal.append(CaptureSessionJournal.RECORD_VAULT_ENCRYPTION_STARTED, 270L, mapOf("pcmBytes" to 960L))
                journal.append(CaptureSessionJournal.RECORD_VAULT_ENCRYPTION_COMPLETED, 290L, mapOf("encryptedBytes" to 1_234L))
                journal.append(
                    CaptureSessionJournal.RECORD_FILE_FINALIZED,
                    300L,
                    mapOf("encryptedBytes" to 1_234L),
                )
            }
            val result = CaptureSessionJournal.scan(journalFile)
            assertTrue(result.valid)
            assertFalse(result.damagedTail)
            assertEquals(7L, result.lastSequence)
            assertTrue(result.finalized)
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun emptyCreatedJournalIsNotMistakenForAValidSession() {
        val directory = Files.createTempDirectory("sqrec-sqj-empty-").toFile()
        val session = UUID.randomUUID()
        val journalFile = File(directory, "session-$session.sqj")
        try {
            CaptureSessionJournal.create(journalFile, session).use { }
            val scan = CaptureSessionJournal.scan(journalFile)
            assertFalse(scan.valid)
            assertTrue(scan.damagedTail)
            assertEquals("empty journal; SESSION_CREATED was not durably recorded", scan.reason)
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun timestampRegressionIsRejectedBeforeAnyJournalBytesAreWritten() {
        val directory = Files.createTempDirectory("sqrec-sqj-time-").toFile()
        val session = UUID.randomUUID()
        val journalFile = File(directory, "session-$session.sqj")
        try {
            CaptureSessionJournal.create(journalFile, session).use { journal ->
                journal.append(CaptureSessionJournal.RECORD_SESSION_CREATED, 200L)
                val before = journalFile.readBytes()
                var rejected = false
                try {
                    journal.append(CaptureSessionJournal.RECORD_CAPTURE_STARTED, 199L)
                } catch (_: IllegalArgumentException) {
                    rejected = true
                }
                assertTrue("monotonic timestamp regression must be rejected", rejected)
                assertEquals(before.toList(), journalFile.readBytes().toList())
                journal.append(CaptureSessionJournal.RECORD_CAPTURE_STARTED, 201L)
            }
            val scan = CaptureSessionJournal.scan(journalFile)
            assertTrue(scan.valid)
            assertEquals(2L, scan.lastSequence)
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun scannerDoesNotAcceptPrematureOrPostFinalizationRecords() {
        val directory = Files.createTempDirectory("sqrec-sqj-terminal-").toFile()
        val session = UUID.randomUUID()
        val journalFile = File(directory, "session-$session.sqj")
        try {
            CaptureSessionJournal.create(journalFile, session).use { journal ->
                journal.append(CaptureSessionJournal.RECORD_SESSION_CREATED, 10L)
                journal.append(CaptureSessionJournal.RECORD_FILE_FINALIZED, 20L)
            }
            val premature = CaptureSessionJournal.scan(journalFile)
            assertFalse("FILE_FINALIZED without encryption completion is invalid", premature.valid)
            assertFalse(premature.finalized)

            journalFile.delete()
            CaptureSessionJournal.create(journalFile, session).use { journal ->
                journal.append(CaptureSessionJournal.RECORD_SESSION_CREATED, 10L)
                journal.append(CaptureSessionJournal.RECORD_CAPTURE_STARTED, 20L)
                journal.append(CaptureSessionJournal.RECORD_CAPTURE_STOP_REQUESTED, 30L)
                journal.append(CaptureSessionJournal.RECORD_CAPTURE_STOPPED, 40L)
                journal.append(CaptureSessionJournal.RECORD_VAULT_ENCRYPTION_STARTED, 50L)
                journal.append(CaptureSessionJournal.RECORD_VAULT_ENCRYPTION_COMPLETED, 60L)
                journal.append(CaptureSessionJournal.RECORD_FILE_FINALIZED, 70L)
                journal.append(CaptureSessionJournal.RECORD_INTEGRITY_INCIDENT, 80L)
            }
            val afterFinal = CaptureSessionJournal.scan(journalFile)
            assertFalse("no records may follow FILE_FINALIZED", afterFinal.valid)
            assertTrue(afterFinal.finalized)
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun scannerRejectsDamagedDigestWithoutModifyingOriginalJournal() {
        val directory = Files.createTempDirectory("sqrec-sqj-corrupt-").toFile()
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
