package com.alinor.sqrecorder.domain

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class VaultV2ContractsTest {
    private fun validV2() = VaultV2EnvelopeContract(
        cipherSuite = VaultV2CipherSuite.AES_256_GCM_CHUNKED_V2,
        fileId = "4c9c0c52-8a93-4a53-bf0d-a6d47f4d1e02",
        fileKeyId = "file-dek-v2",
        fileSaltHex = "ab".repeat(32),
        noncePrefixHex = "0123abcd",
        chunkSizeBytes = VaultV2EnvelopeContract.CHUNK_SIZE_BYTES,
        plaintextBytes = 1L,
        chunkCount = 1L,
        headerMacBase64 = "A".repeat(43) + "=",
        recipients = listOf(
            VaultV2RecipientWrap(
                suite = VaultV2WrapSuite.RSA_OAEP_SHA256_MGF1_SHA256_EMPTY_LABEL,
                recipientKeyId = "android-keystore-key-v2",
                wrappedDekBase64 = "A".repeat(512),
            ),
        ),
    )

    @Test
    fun validV2MetadataPassesAndDoesNotChangeV1Contract() {
        assertNull(validV2().validate())
        assertEquals(1_048_576, VaultEnvelopeHeader.V1_CHUNK_SIZE_BYTES)
        assertEquals(2, VaultV2EnvelopeContract.VERSION)
    }

    @Test
    fun rejectsUnknownVersionAndMissingAuthenticatedHeader() {
        assertEquals(
            VaultV2ContractError.UNSUPPORTED_VERSION,
            validV2().copy(formatVersion = 1).validate(),
        )
        assertEquals(
            VaultV2ContractError.INVALID_HEADER_MAC_ENCODING,
            validV2().copy(headerMacBase64 = "AA==").validate(),
        )
    }

    @Test
    fun rejectsMalformedSaltAndNonceAndChunkCount() {
        assertEquals(
            VaultV2ContractError.INVALID_FILE_SALT,
            validV2().copy(fileSaltHex = "ab").validate(),
        )
        assertEquals(
            VaultV2ContractError.INVALID_NONCE_PREFIX,
            validV2().copy(noncePrefixHex = "nothex!!").validate(),
        )
        assertEquals(
            VaultV2ContractError.CHUNK_COUNT_MISMATCH,
            validV2().copy(chunkCount = 0L).validate(),
        )
    }

    @Test
    fun ecdhRecipientRequiresEphemeralKeyAndNonce() {
        val recipient = VaultV2RecipientWrap(
            suite = VaultV2WrapSuite.ECDH_P256_HKDF_SHA256_AES256_GCM,
            recipientKeyId = "apple-key-v2",
            wrappedDekBase64 = "A".repeat(84),
            ephemeralPublicKeyBase64 = "AQ==",
            wrapNonceHex = "01".repeat(12),
        )
        assertNull(validV2().copy(recipients = listOf(recipient)).validate())
        assertEquals(
            VaultV2ContractError.INVALID_ECDH_WRAP,
            validV2().copy(
                recipients = listOf(recipient.copy(wrapNonceHex = null)),
            ).validate(),
        )
    }

    @Test
    fun rejectsDuplicateRecipientAndNoncanonicalWrappedKey() {
        val first = validV2().recipients.single()
        assertEquals(
            VaultV2ContractError.DUPLICATE_RECIPIENT,
            validV2().copy(recipients = listOf(first, first.copy(wrappedDekBase64 = "B".repeat(512)))).validate(),
        )
        assertEquals(
            VaultV2ContractError.INVALID_WRAPPED_DEK,
            validV2().copy(recipients = listOf(first.copy(wrappedDekBase64 = "A=AA"))).validate(),
        )
        assertEquals(
            VaultV2ContractError.INVALID_HEADER_MAC_ENCODING,
            validV2().copy(headerMacBase64 = "B".repeat(43) + "=").validate(),
        )
    }

    @Test
    fun v2RecipientIdsUseCanonicalAsciiOrderAndPermitContractColon() {
        val first = validV2().recipients.single().copy(recipientKeyId = "device:primary")
        val next = first.copy(recipientKeyId = "z-device")
        assertNull(validV2().copy(recipients = listOf(first, next)).validate())
        assertEquals(
            VaultV2ContractError.NONCANONICAL_RECIPIENT_ORDER,
            validV2().copy(recipients = listOf(next, first)).validate(),
        )
    }

    @Test
    fun explicitApi23Rsa3072SuiteRequiresExactCiphertextSizeAndNoEcdhFields() {
        val recipient = VaultV2RecipientWrap(
            suite = VaultV2WrapSuite.RSA3072_OAEP_SHA256_MGF1_SHA1_EMPTY_LABEL,
            recipientKeyId = "android-v2-rsa3072-mgf1sha1",
            wrappedDekBase64 = "A".repeat(VaultV2EnvelopeContract.RSA3072_CIPHERTEXT_BASE64_LENGTH),
        )
        assertNull(validV2().copy(recipients = listOf(recipient)).validate())
        assertEquals(
            VaultV2ContractError.INVALID_RSA_WRAP,
            validV2().copy(
                recipients = listOf(recipient.copy(wrappedDekBase64 = "A".repeat(508))),
            ).validate(),
        )
        assertEquals(
            VaultV2ContractError.INVALID_RSA_WRAP,
            validV2().copy(
                recipients = listOf(recipient.copy(ephemeralPublicKeyBase64 = "AQ==")),
            ).validate(),
        )
    }
}
