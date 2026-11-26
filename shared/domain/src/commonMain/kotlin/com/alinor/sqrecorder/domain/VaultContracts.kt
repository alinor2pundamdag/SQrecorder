package com.alinor.sqrecorder.domain

/**
 * Cross-platform Vault format and policy contracts.
 *
 * Cryptographic operations are supplied by a platform/native provider; this
 * module must never implement cryptography or retain plaintext key material.
 */
public enum class VaultCipherSuite {
    AES_256_GCM_CHUNKED_V1,
}

public enum class VaultKeyWrapSuite {
    RSA_OAEP_SHA256_V1,
}

public enum class VaultAccessMode {
    AUTHENTICATED,
    ENCRYPT_ONLY,
}

public enum class VaultFileState {
    ENCRYPTING,
    SEALED,
    INCOMPLETE,
    AUTHENTICATION_REQUIRED,
    KEY_INVALIDATED,
    CORRUPT,
}

public data class VaultKeyWrap(
    public val suite: VaultKeyWrapSuite,
    public val recipientKeyId: String,
    public val wrappedFileKey: ByteArray,
)

public data class VaultEnvelopeHeader(
    public val version: Int,
    public val cipherSuite: VaultCipherSuite,
    public val fileId: String,
    public val fileKeyId: String,
    public val noncePrefix: ByteArray,
    public val chunkSizeBytes: Int,
    public val plaintextBytes: Long,
    public val chunkCount: Long,
    public val keyWraps: List<VaultKeyWrap>,
) {
    public fun validate(): VaultContractError? {
        if (version != 1) return VaultContractError.UNSUPPORTED_ENVELOPE_VERSION
        if (fileId.isBlank() || fileKeyId.isBlank()) return VaultContractError.INVALID_IDENTIFIER
        if (noncePrefix.size != NONCE_PREFIX_BYTES) return VaultContractError.INVALID_NONCE_PREFIX
        if (chunkSizeBytes != V1_CHUNK_SIZE_BYTES) return VaultContractError.INVALID_CHUNK_SIZE
        if (plaintextBytes < 0L || chunkCount < 0L) return VaultContractError.INVALID_LENGTH
        val expectedChunks = if (plaintextBytes == 0L) 0L
            else ((plaintextBytes - 1L) / chunkSizeBytes.toLong()) + 1L
        if (chunkCount != expectedChunks) return VaultContractError.CHUNK_COUNT_MISMATCH
        if (keyWraps.isEmpty()) return VaultContractError.MISSING_KEY_WRAP
        if (keyWraps.any { it.recipientKeyId.isBlank() || it.wrappedFileKey.isEmpty() }) {
            return VaultContractError.INVALID_KEY_WRAP
        }
        return null
    }

    public companion object {
        public const val V1_CHUNK_SIZE_BYTES: Int = 1_048_576
        public const val NONCE_PREFIX_BYTES: Int = 4
        public const val GCM_NONCE_BYTES: Int = 12
        public const val GCM_TAG_BYTES: Int = 16
    }
}

public data class VaultChunkDescriptor(
    public val index: Long,
    public val plaintextBytes: Int,
    public val ciphertextBytes: Int,
) {
    public fun validate(header: VaultEnvelopeHeader): VaultContractError? {
        if (index < 0L || index >= header.chunkCount) return VaultContractError.INVALID_CHUNK_INDEX
        if (plaintextBytes < 0 || plaintextBytes > header.chunkSizeBytes) {
            return VaultContractError.INVALID_LENGTH
        }
        if (ciphertextBytes != plaintextBytes + VaultEnvelopeHeader.GCM_TAG_BYTES) {
            return VaultContractError.CIPHERTEXT_LENGTH_MISMATCH
        }
        return null
    }
}

/** Construct a 96-bit GCM nonce: 32-bit per-file prefix || 64-bit big-endian chunk index. */
public fun vaultNonceV1(prefix: ByteArray, chunkIndex: Long): ByteArray {
    require(prefix.size == VaultEnvelopeHeader.NONCE_PREFIX_BYTES)
    require(chunkIndex >= 0L)
    return ByteArray(VaultEnvelopeHeader.GCM_NONCE_BYTES).also { nonce ->
        prefix.copyInto(nonce, destinationOffset = 0)
        for (i in 0 until 8) {
            nonce[4 + i] = ((chunkIndex ushr ((7 - i) * 8)) and 0xFF).toByte()
        }
    }
}

public enum class VaultContractError {
    UNSUPPORTED_ENVELOPE_VERSION,
    INVALID_IDENTIFIER,
    INVALID_NONCE_PREFIX,
    INVALID_CHUNK_SIZE,
    INVALID_LENGTH,
    CHUNK_COUNT_MISMATCH,
    MISSING_KEY_WRAP,
    INVALID_KEY_WRAP,
    INVALID_CHUNK_INDEX,
    CIPHERTEXT_LENGTH_MISMATCH,
}

public enum class JournalRecordType {
    SESSION_CREATED,
    CAPTURE_STARTED,
    CAPTURE_STOP_REQUESTED,
    CAPTURE_STOPPED,
    INTEGRITY_INCIDENT,
    FILE_FINALIZED,
    VAULT_ENCRYPTION_STARTED,
    VAULT_ENCRYPTION_COMPLETED,
    RECOVERY_COMPLETED,
    MIGRATION_APPENDED,
}

public data class JournalRecordHeader(
    public val formatVersion: Int,
    public val sequence: Long,
    public val monotonicTimestampNs: Long,
    public val sessionId: SessionId,
    public val recordType: JournalRecordType,
    public val previousRecordDigest: ByteArray,
    public val recordDigest: ByteArray,
) {
    public fun validate(expectedSequence: Long, expectedPreviousDigest: ByteArray): Boolean =
        formatVersion == 1 &&
            sequence == expectedSequence &&
            monotonicTimestampNs >= 0L &&
            previousRecordDigest.contentEquals(expectedPreviousDigest) &&
            previousRecordDigest.size == JOURNAL_DIGEST_BYTES &&
            recordDigest.size == JOURNAL_DIGEST_BYTES

    public companion object {
        public const val JOURNAL_DIGEST_BYTES: Int = 32
    }
}

public enum class JournalAppendStatus {
    DURABLE,
    FAILED,
}

public data class JournalAppendResult(
    public val status: JournalAppendStatus,
    public val committedSequence: Long?,
)

public interface SessionJournal {
    /** Append is ordered and durable before DURABLE is returned. No overwrite/truncate API exists. */
    public fun append(record: JournalRecordHeader): JournalAppendResult
}

/** Key wrapping is asymmetric: public-key wrap; private-key unwrap requires authenticated access. */
public interface VaultKeyAccess {
    public fun currentPublicWrappingKeyId(): String
    public fun wrapFileKeyWithPublicKey(fileKeyHandle: String, recipientKeyId: String): VaultKeyWrap
    public fun unwrapFileKeyWithPrivateKey(wrap: VaultKeyWrap, accessMode: VaultAccessMode): String
}

/** Cipher provider owns key bytes and authenticates header + chunk metadata as AAD. */
public interface VaultChunkCipher {
    public fun encryptChunk(
        fileKeyHandle: String,
        nonce: ByteArray,
        associatedData: ByteArray,
        plaintext: ByteArray,
    ): ByteArray

    public fun decryptChunk(
        fileKeyHandle: String,
        nonce: ByteArray,
        associatedData: ByteArray,
        ciphertextAndTag: ByteArray,
        accessMode: VaultAccessMode,
    ): ByteArray
}
