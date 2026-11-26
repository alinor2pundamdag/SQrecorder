package com.alinor.sqrecorder.domain

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNull

class VaultContractsTest {
    private fun validHeader(plaintextBytes: Long = 1L): VaultEnvelopeHeader {
        val chunks = if (plaintextBytes == 0L) 0L
            else ((plaintextBytes - 1L) / VaultEnvelopeHeader.V1_CHUNK_SIZE_BYTES) + 1L
        return VaultEnvelopeHeader(
            version = 1,
            cipherSuite = VaultCipherSuite.AES_256_GCM_CHUNKED_V1,
            fileId = "4c9c0c52-8a93-4a53-bf0d-a6d47f4d1e02",
            fileKeyId = "device-key-v1",
            noncePrefixHex = "0123abcd",
            chunkSizeBytes = VaultEnvelopeHeader.V1_CHUNK_SIZE_BYTES,
            plaintextBytes = plaintextBytes,
            chunkCount = chunks,
            keyWraps = listOf(
                VaultKeyWrap(
                    suite = VaultKeyWrapSuite.RSA_OAEP_SHA256_V1,
                    recipientKeyId = "device-wrap-key-v1",
                    wrappedFileKey = "base64-wrapped-key",
                ),
            ),
        )
    }

    @Test
    fun validEnvelopeAndChunkDescriptorPassContract() {
        val header = validHeader(plaintextBytes = 10L)
        assertNull(header.validate())
        assertNull(VaultChunkDescriptor(index = 0L, plaintextBytes = 10, ciphertextBytes = 26).validate(header))
    }

    @Test
    fun envelopeRejectsChunkCountAndNoncePrefixMismatch() {
        assertEquals(
            VaultContractError.CHUNK_COUNT_MISMATCH,
            validHeader(plaintextBytes = 10L).copy(chunkCount = 2L).validate(),
        )
        assertEquals(
            VaultContractError.INVALID_NONCE_PREFIX,
            validHeader().copy(noncePrefixHex = "nothex!!").validate(),
        )
    }

    @Test
    fun nonceEncodingIsStableAndDistinctByChunkIndex() {
        val prefix = byteArrayOf(0x01, 0x23, 0xAB.toByte(), 0xCD.toByte())
        val first = vaultNonceV1(prefix, 0L)
        val second = vaultNonceV1(prefix, 1L)
        assertEquals(12, first.size)
        assertEquals(12, second.size)
        assertEquals(prefix.toList(), first.take(4).toList())
        assertEquals(1.toByte(), second.last())
        assertNotEquals(first.toList(), second.toList())
    }

    @Test
    fun journalRequiresSequenceAndPreviousDigestToMatch() {
        val record = JournalRecord(
            formatVersion = 1,
            sequence = 7L,
            monotonicTimestampNs = 100L,
            sessionId = SessionId("journal-test"),
            recordType = JournalRecordType.CAPTURE_STARTED,
            canonicalPayload = """{"captureEpoch":"1"}""",
            previousRecordDigestHex = JournalRecord.GENESIS_DIGEST_HEX,
        )
        assertEquals(true, record.validate(7L, JournalRecord.GENESIS_DIGEST_HEX))
        assertEquals(false, record.validate(8L, JournalRecord.GENESIS_DIGEST_HEX))
        assertEquals(false, record.validate(7L, "ab"))
    }
}
