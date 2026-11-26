package com.alinor.sqrecorder.domain

/** Cross-platform Vault format and policy contracts; cryptography is provider-owned. */
public enum class VaultCipherSuite { AES_256_GCM_CHUNKED_V1 }
public enum class VaultKeyWrapSuite { RSA_OAEP_SHA256_V1 }
public enum class VaultAccessMode { AUTHENTICATED, ENCRYPT_ONLY }
public enum class VaultFileState {
    ENCRYPTING, SEALED, INCOMPLETE, AUTHENTICATION_REQUIRED, KEY_INVALIDATED, CORRUPT,
}

/** Opaque provider-owned handle; identifier is not key material. */
@JvmInline
public value class VaultFileKeyHandle(public val opaqueId: String)

public data class VaultKeyWrap(
    public val suite: VaultKeyWrapSuite,
    public val recipientKeyId: String,
    /** Standard base64 encoded wrapped DEK; plaintext DEK must never enter this model. */
    public val wrappedFileKeyBase64: String,
)

public data class VaultEnvelopeHeader(
    public val version: Int,
    public val cipherSuite: VaultCipherSuite,
    public val fileId: String,
    public val fileKeyId: String,
    /** Exactly 8 lowercase hex characters representing a 4-byte nonce prefix. */
    public val noncePrefixHex: String,
    public val chunkSizeBytes: Int,
    public val plaintextBytes: Long,
    public val chunkCount: Long,
    public val keyWraps: List<VaultKeyWrap>,
) {
    public fun validate(): VaultContractError? {
        if (version != 1) return VaultContractError.UNSUPPORTED_ENVELOPE_VERSION
        if (!fileId.isCanonicalUuid() || !fileKeyId.isSafeKeyId()) {
            return VaultContractError.INVALID_IDENTIFIER
        }
        if (!noncePrefixHex.isLowerHexOfLength(NONCE_PREFIX_HEX_CHARS)) {
            return VaultContractError.INVALID_NONCE_PREFIX
        }
        if (chunkSizeBytes != V1_CHUNK_SIZE_BYTES) return VaultContractError.INVALID_CHUNK_SIZE
        if (plaintextBytes < 0L || chunkCount < 0L) return VaultContractError.INVALID_LENGTH
        val expectedChunks = if (plaintextBytes == 0L) 0L
            else ((plaintextBytes - 1L) / chunkSizeBytes.toLong()) + 1L
        if (chunkCount != expectedChunks) return VaultContractError.CHUNK_COUNT_MISMATCH
        if (keyWraps.isEmpty()) return VaultContractError.MISSING_KEY_WRAP
        if (keyWraps.any {
                !it.recipientKeyId.isSafeKeyId() || !it.wrappedFileKeyBase64.isStandardBase64()
            }
        ) return VaultContractError.INVALID_KEY_WRAP
        if (keyWraps.map { it.recipientKeyId }.distinct().size != keyWraps.size) {
            return VaultContractError.DUPLICATE_KEY_RECIPIENT
        }
        return null
    }

    public companion object {
        public const val V1_CHUNK_SIZE_BYTES: Int = 1_048_576
        public const val NONCE_PREFIX_BYTES: Int = 4
        public const val NONCE_PREFIX_HEX_CHARS: Int = NONCE_PREFIX_BYTES * 2
        public const val GCM_NONCE_BYTES: Int = 12
        public const val GCM_TAG_BYTES: Int = 16
        public const val MAX_KEY_ID_CHARS: Int = 128
        public const val MAX_WRAPPED_KEY_BASE64_CHARS: Int = 16_384
    }
}

public data class VaultChunkDescriptor(
    public val index: Long,
    public val plaintextBytes: Int,
    public val ciphertextBytes: Int,
) {
    public fun validate(header: VaultEnvelopeHeader): VaultContractError? {
        header.validate()?.let { return it }
        if (index < 0L || index >= header.chunkCount) return VaultContractError.INVALID_CHUNK_INDEX
        if (plaintextBytes < 0 || plaintextBytes > header.chunkSizeBytes) {
            return VaultContractError.INVALID_LENGTH
        }
        val offset = index * header.chunkSizeBytes.toLong()
        val expectedPlaintextBytes = minOf(
            header.chunkSizeBytes.toLong(),
            header.plaintextBytes - offset,
        ).toInt()
        if (plaintextBytes != expectedPlaintextBytes) {
            return VaultContractError.CHUNK_PLAINTEXT_LENGTH_MISMATCH
        }
        if (ciphertextBytes != plaintextBytes + VaultEnvelopeHeader.GCM_TAG_BYTES) {
            return VaultContractError.CIPHERTEXT_LENGTH_MISMATCH
        }
        return null
    }
}

/** 96-bit GCM nonce: 32-bit per-file prefix || 64-bit big-endian chunk index. */
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

private fun String.isLowerHexOfLength(expectedLength: Int): Boolean =
    length == expectedLength && all { it in '0'..'9' || it in 'a'..'f' }

private fun String.isCanonicalUuid(): Boolean =
    length == 36 &&
        this[8] == '-' && this[13] == '-' && this[18] == '-' && this[23] == '-' &&
        filterNot { it == '-' }.isLowerHexOfLength(32)

private fun String.isSafeKeyId(): Boolean =
    isNotEmpty() && length <= VaultEnvelopeHeader.MAX_KEY_ID_CHARS &&
        all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it in '-' || it in '_' || it in '.' }

private fun String.isStandardBase64(): Boolean {
    if (isEmpty() || length > VaultEnvelopeHeader.MAX_WRAPPED_KEY_BASE64_CHARS || length % 4 != 0) {
        return false
    }
    var padding = 0
    for (i in indices) {
        val c = this[i]
        if (c == '=') {
            padding++
            if (i < length - 2 || padding > 2) return false
        } else if (!(c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' || c == '+' || c == '/')) {
            return false
        }
    }
    return true
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
    DUPLICATE_KEY_RECIPIENT,
    INVALID_CHUNK_INDEX,
    CHUNK_PLAINTEXT_LENGTH_MISMATCH,
    CIPHERTEXT_LENGTH_MISMATCH,
}

public enum class JournalRecordType {
    SESSION_CREATED, CAPTURE_STARTED, CAPTURE_STOP_REQUESTED, CAPTURE_STOPPED,
    INTEGRITY_INCIDENT, FILE_FINALIZED, VAULT_ENCRYPTION_STARTED,
    VAULT_ENCRYPTION_COMPLETED, RECOVERY_COMPLETED, MIGRATION_APPENDED,
}

/** Canonical UTF-8 metadata only; never PCM, plaintext, or key material. */
public data class JournalRecord(
    public val formatVersion: Int,
    public val sequence: Long,
    public val monotonicTimestampNs: Long,
    public val sessionId: SessionId,
    public val recordType: JournalRecordType,
    public val canonicalPayload: String,
    public val previousRecordDigestHex: String,
) {
    public fun validate(expectedSequence: Long, expectedPreviousDigestHex: String): Boolean =
        formatVersion == 1 &&
            sequence > 0L &&
            sequence == expectedSequence &&
            monotonicTimestampNs >= 0L &&
            sessionId.value.isNotBlank() &&
            previousRecordDigestHex.isLowerHexOfLength(JOURNAL_DIGEST_HEX_CHARS) &&
            previousRecordDigestHex == expectedPreviousDigestHex &&
            canonicalPayload.isNotBlank()

    public companion object {
        public const val JOURNAL_DIGEST_BYTES: Int = 32
        public const val JOURNAL_DIGEST_HEX_CHARS: Int = JOURNAL_DIGEST_BYTES * 2
        public const val GENESIS_DIGEST_HEX: String =
            "0000000000000000000000000000000000000000000000000000000000000000"
    }
}

public enum class JournalAppendStatus { DURABLE, FAILED }

public data class JournalAppendResult(
    public val status: JournalAppendStatus,
    public val committedSequence: Long?,
    public val committedDigestHex: String?,
)

public interface SessionJournal {
    /** Single-writer append; compute digest and fsync before returning DURABLE. No rewrite/truncate API. */
    public fun append(record: JournalRecord): JournalAppendResult
}

/** Public key wraps a random per-file DEK; private-key unwrap requires authenticated access. */
public interface VaultKeyAccess {
    public fun createRandomFileKeyHandle(): VaultFileKeyHandle
    public fun currentPublicWrappingKeyId(): String
    public fun wrapFileKeyWithPublicKey(
        fileKeyHandle: VaultFileKeyHandle,
        recipientKeyId: String,
    ): VaultKeyWrap
    public fun unwrapFileKeyWithPrivateKey(
        wrap: VaultKeyWrap,
        accessMode: VaultAccessMode,
    ): VaultFileKeyHandle
}

/** Provider owns DEK bytes and authenticates immutable envelope + chunk metadata as AAD. */
public interface VaultChunkCipher {
    public fun encryptChunk(
        fileKeyHandle: VaultFileKeyHandle,
        nonce: ByteArray,
        associatedData: ByteArray,
        plaintext: ByteArray,
    ): ByteArray

    /** Must reject ENCRYPT_ONLY; authentication/tag failure must return no plaintext. */
    public fun decryptChunk(
        fileKeyHandle: VaultFileKeyHandle,
        nonce: ByteArray,
        associatedData: ByteArray,
        ciphertextAndTag: ByteArray,
        accessMode: VaultAccessMode,
    ): ByteArray
}
