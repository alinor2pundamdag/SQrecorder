package com.alinor.sqrecorder.domain

/**
 * SQVE v2 metadata contract. This validates structure only; the Rust crypto
 * implementation/provider must verify the header MAC, key-wrap operation and
 * AEAD tags before any plaintext is accepted.
 *
 * v1 is represented by VaultEnvelopeHeader and is deliberately not accepted
 * by this v2 type. No implicit downgrade or suite substitution is permitted.
 */
public enum class VaultV2CipherSuite {
    AES_256_GCM_CHUNKED_V2,
}

/** Immutable IDs name exact OAEP/ECDH parameters; implementations may not negotiate silently. */
public enum class VaultV2WrapSuite {
    RSA_OAEP_SHA256_MGF1_SHA256_EMPTY_LABEL,
    ECDH_P256_HKDF_SHA256_AES256_GCM,
}

public data class VaultV2RecipientWrap(
    public val suite: VaultV2WrapSuite,
    public val recipientKeyId: String,
    /** RSA ciphertext, or ECDH-derived AES-GCM ciphertext+tag; Base64 standard encoding. */
    public val wrappedDekBase64: String,
    /** DER SubjectPublicKeyInfo of the ephemeral P-256 key for ECDH only. */
    public val ephemeralPublicKeyBase64: String? = null,
    /** 96-bit AES-GCM nonce for ECDH wrapping, 24 lowercase hex chars. */
    public val wrapNonceHex: String? = null,
)

public data class VaultV2EnvelopeContract(
    public val formatVersion: Int = 2,
    public val cipherSuite: VaultV2CipherSuite,
    public val fileId: String,
    public val fileKeyId: String,
    /** 32-byte per-file random salt as 64 lowercase hex chars. */
    public val fileSaltHex: String,
    /** 4-byte random nonce prefix as 8 lowercase hex chars. */
    public val noncePrefixHex: String,
    public val chunkSizeBytes: Int,
    public val plaintextBytes: Long,
    public val chunkCount: Long,
    /** HMAC-SHA256 header authenticator: 32 bytes, standard Base64 (44 chars). */
    public val headerMacBase64: String,
    public val recipients: List<VaultV2RecipientWrap>,
) {
    public fun validate(): VaultV2ContractError? {
        if (formatVersion != VERSION) return VaultV2ContractError.UNSUPPORTED_VERSION
        if (cipherSuite != VaultV2CipherSuite.AES_256_GCM_CHUNKED_V2) {
            return VaultV2ContractError.UNSUPPORTED_CIPHER_SUITE
        }
        if (!fileId.isCanonicalUuid() || !fileKeyId.isSafeId()) {
            return VaultV2ContractError.INVALID_IDENTIFIER
        }
        if (!fileSaltHex.isLowerHex(64)) return VaultV2ContractError.INVALID_FILE_SALT
        if (!noncePrefixHex.isLowerHex(8)) return VaultV2ContractError.INVALID_NONCE_PREFIX
        if (chunkSizeBytes != CHUNK_SIZE_BYTES) return VaultV2ContractError.INVALID_CHUNK_SIZE
        if (plaintextBytes < 0L || chunkCount < 0L) return VaultV2ContractError.INVALID_LENGTH
        val expectedChunks = if (plaintextBytes == 0L) 0L
            else ((plaintextBytes - 1L) / CHUNK_SIZE_BYTES.toLong()) + 1L
        if (chunkCount != expectedChunks) return VaultV2ContractError.CHUNK_COUNT_MISMATCH
        if (!headerMacBase64.isCanonicalBase64() || headerMacBase64.length != 44 ||
            !headerMacBase64.endsWith("=")
        ) return VaultV2ContractError.INVALID_HEADER_MAC_ENCODING
        if (recipients.isEmpty()) return VaultV2ContractError.MISSING_RECIPIENT
        if (recipients.size > MAX_RECIPIENTS) return VaultV2ContractError.INVALID_WRAPPED_DEK
        if (recipients.any { !it.recipientKeyId.isSafeV2RecipientId() }) {
            return VaultV2ContractError.INVALID_RECIPIENT_ID
        }
        if (recipients.map { it.recipientKeyId }.distinct().size != recipients.size) {
            return VaultV2ContractError.DUPLICATE_RECIPIENT
        }
        // V2 wire records are strictly sorted by the raw ASCII recipient ID.
        if (recipients.zipWithNext().any { (left, right) ->
                left.recipientKeyId >= right.recipientKeyId
            }
        ) return VaultV2ContractError.NONCANONICAL_RECIPIENT_ORDER
        for (recipient in recipients) {
            if (recipient.wrappedDekBase64.length > MAX_WRAPPED_DEK_BASE64_BYTES ||
                !recipient.wrappedDekBase64.isCanonicalBase64()
            ) {
                return VaultV2ContractError.INVALID_WRAPPED_DEK
            }
            when (recipient.suite) {
                VaultV2WrapSuite.RSA_OAEP_SHA256_MGF1_SHA256_EMPTY_LABEL -> {
                    if (recipient.wrappedDekBase64.length < MIN_RSA_2048_CIPHERTEXT_BASE64 ||
                        recipient.ephemeralPublicKeyBase64 != null ||
                        recipient.wrapNonceHex != null
                    ) return VaultV2ContractError.INVALID_RSA_WRAP
                }
                VaultV2WrapSuite.ECDH_P256_HKDF_SHA256_AES256_GCM -> {
                    if (recipient.wrappedDekBase64.length != ECDH_WRAPPED_DEK_BASE64_LENGTH ||
                        recipient.ephemeralPublicKeyBase64.isNullOrEmpty() ||
                        recipient.ephemeralPublicKeyBase64.length > MAX_EPHEMERAL_KEY_BASE64_CHARS ||
                        !recipient.ephemeralPublicKeyBase64.isCanonicalBase64() ||
                        recipient.wrapNonceHex?.isLowerHex(24) != true
                    ) return VaultV2ContractError.INVALID_ECDH_WRAP
                }
            }
        }
        return null
    }

    public companion object {
        public const val VERSION: Int = 2
        public const val DEK_BYTES: Int = 32
        public const val GCM_TAG_BYTES: Int = 16
        public const val GCM_NONCE_BYTES: Int = 12
        public const val CHUNK_SIZE_BYTES: Int = 1_048_576
        public const val MIN_RSA_2048_CIPHERTEXT_BASE64: Int = 344
        public const val ECDH_WRAPPED_DEK_BASE64_LENGTH: Int = 64
        public const val MAX_WRAPPED_DEK_BASE64_BYTES: Int = 16_384
        public const val MAX_RECIPIENTS: Int = 16
        public const val MAX_EPHEMERAL_KEY_BASE64_CHARS: Int = 512
    }
}

public enum class VaultV2ContractError {
    UNSUPPORTED_VERSION,
    UNSUPPORTED_CIPHER_SUITE,
    INVALID_IDENTIFIER,
    INVALID_FILE_SALT,
    INVALID_NONCE_PREFIX,
    INVALID_CHUNK_SIZE,
    INVALID_LENGTH,
    CHUNK_COUNT_MISMATCH,
    INVALID_HEADER_MAC_ENCODING,
    MISSING_RECIPIENT,
    INVALID_RECIPIENT_ID,
    DUPLICATE_RECIPIENT,
    INVALID_WRAPPED_DEK,
    INVALID_RSA_WRAP,
    INVALID_ECDH_WRAP,
}

/** Strict common-source lexical checks; crypto decoding/authentication is Rust/provider-owned. */
private fun String.isCanonicalBase64(): Boolean {
    if (isEmpty() || length % 4 != 0) return false
    var padding = 0
    var sawPadding = false
    for (i in indices) {
        val c = this[i]
        if (c == '=') {
            sawPadding = true
            padding++
            if (i < length - 2 || padding > 2) return false
        } else {
            if (sawPadding) return false
            if (!(c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' || c == '+' || c == '/')) {
                return false
            }
        }
    }
    if (padding == 1 && (base64Value(this[length - 2]) and 0x03) != 0) return false
    if (padding == 2 && (base64Value(this[length - 3]) and 0x0f) != 0) return false
    return true
}

private fun base64Value(c: Char): Int = when (c) {
    in 'A'..'Z' -> c.code - 'A'.code
    in 'a'..'z' -> c.code - 'a'.code + 26
    in '0'..'9' -> c.code - '0'.code + 52
    '+' -> 62
    '/' -> 63
    else -> -1
}

private fun String.isLowerHex(expected: Int): Boolean =
    length == expected && all { it in '0'..'9' || it in 'a'..'f' }

private fun String.isSafeId(): Boolean =
    isNotEmpty() && length <= 128 &&
        all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '-' || it == '_' || it == '.' }

private fun String.isSafeV2RecipientId(): Boolean =
    isNotEmpty() && length <= 128 &&
        all {
            it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' ||
                it == '-' || it == '_' || it == '.' || it == ':'
        }

private fun String.isCanonicalUuid(): Boolean =
    length == 36 &&
        this[8] == '-' && this[13] == '-' && this[18] == '-' && this[23] == '-' &&
        filterNot { it == '-' }.isLowerHex(32)
