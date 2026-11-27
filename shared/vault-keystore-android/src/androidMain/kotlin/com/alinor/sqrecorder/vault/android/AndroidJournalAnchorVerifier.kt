package com.alinor.sqrecorder.vault.android

import com.alinor.sqrecorder.domain.JournalSignatureAnchor
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * Verifies an authenticated SQJ anchor against a retained public-key record.
 *
 * Resolver implementations must use a durable, append-only key registry and must
 * never return a key solely because its alias is currently active. Historical
 * keys are required to validate anchors created before rotation.
 */
public fun interface JournalAnchorPublicKeyResolver {
    public fun resolveEncodedPublicKey(keyId: String): ByteArray?
}

public enum class JournalAnchorVerificationResult {
    VALID,
    INVALID_METADATA,
    KEY_NOT_FOUND,
    KEY_ID_MISMATCH,
    INVALID_SIGNATURE,
    UNSUPPORTED_ALGORITHM,
}

/** Android/JVM verifier; signature preimage is byte-for-byte shared with signer. */
public class AndroidJournalAnchorVerifier(
    private val keyResolver: JournalAnchorPublicKeyResolver,
) {
    public fun verify(anchor: JournalSignatureAnchor): JournalAnchorVerificationResult {
        if (!anchor.validate() ||
            anchor.signatureAlgorithmId != SIGNATURE_ID ||
            anchor.sequence <= 0L ||
            !anchor.digestHex.matches(Regex("[0-9a-f]{64}"))
        ) return JournalAnchorVerificationResult.INVALID_METADATA

        val encodedKey = keyResolver.resolveEncodedPublicKey(anchor.signingKeyId)
            ?: return JournalAnchorVerificationResult.KEY_NOT_FOUND
        if (publicKeyId(encodedKey) != anchor.signingKeyId) {
            return JournalAnchorVerificationResult.KEY_ID_MISMATCH
        }

        return try {
            val publicKey = KeyFactory.getInstance("EC")
                .generatePublic(X509EncodedKeySpec(encodedKey))
            val verifier = Signature.getInstance("SHA256withECDSA")
            verifier.initVerify(publicKey)
            verifier.update(
                journalAnchorSigningPayload(
                    anchor.sequence,
                    anchor.digestHex,
                    anchor.signingKeyId,
                    anchor.authenticationEpoch,
                    anchor.monotonicTimestampNs,
                ),
            )
            val signatureBytes = decodeStandardBase64(anchor.signatureBase64)
                ?: return JournalAnchorVerificationResult.INVALID_SIGNATURE
            if (verifier.verify(signatureBytes)) JournalAnchorVerificationResult.VALID
            else JournalAnchorVerificationResult.INVALID_SIGNATURE
        } catch (_: java.security.NoSuchAlgorithmException) {
            JournalAnchorVerificationResult.UNSUPPORTED_ALGORITHM
        } catch (_: Exception) {
            JournalAnchorVerificationResult.INVALID_SIGNATURE
        }
    }

    private companion object {
        const val SIGNATURE_ID = "ecdsa-p256-sha256-v1"
    }
}

/** Must match AndroidJournalAnchorSigner.signingKeyId() exactly. */
internal fun publicKeyId(encodedPublicKey: ByteArray): String {
    val fingerprint = MessageDigest.getInstance("SHA-256")
        .digest(encodedPublicKey)
        .take(16)
        .joinToString("") { "%02x".format(it) }
    return "ecdsa-p256-sha256-v1-$fingerprint"
}

/** Android API-23-compatible standard Base64 decoder; avoids mocked android.util.Base64 in host tests. */
private fun decodeStandardBase64(value: String): ByteArray? {
    if (value.isEmpty() || value.length % 4 != 0) return null
    val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    val padding = value.takeLastWhile { it == '=' }.length
    if (padding > 2 || value.dropLast(padding).any { it == '=' }) return null
    val output = ByteArray(value.length / 4 * 3 - padding)
    var out = 0
    var i = 0
    while (i < value.length) {
        val a = alphabet.indexOf(value[i])
        val b = alphabet.indexOf(value[i + 1])
        val c = if (value[i + 2] == '=') 0 else alphabet.indexOf(value[i + 2])
        val d = if (value[i + 3] == '=') 0 else alphabet.indexOf(value[i + 3])
        if (a < 0 || b < 0 || c < 0 || d < 0) return null
        val block = (a shl 18) or (b shl 12) or (c shl 6) or d
        if (out < output.size) output[out++] = (block ushr 16).toByte()
        if (out < output.size) output[out++] = (block ushr 8).toByte()
        if (out < output.size) output[out++] = block.toByte()
        i += 4
    }
    if (padding == 1 && (alphabet.indexOf(value[value.length - 2]) and 0x03) != 0) return null
    if (padding == 2 && (alphabet.indexOf(value[value.length - 3]) and 0x0f) != 0) return null
    return output
}
