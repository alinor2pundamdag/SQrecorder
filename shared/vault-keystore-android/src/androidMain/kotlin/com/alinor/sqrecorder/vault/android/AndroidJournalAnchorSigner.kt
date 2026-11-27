package com.alinor.sqrecorder.vault.android

import android.os.Build
import android.os.SystemClock
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import android.util.Base64
import com.alinor.sqrecorder.domain.JournalAnchorSigner
import com.alinor.sqrecorder.domain.JournalSignatureAnchor
import com.alinor.sqrecorder.domain.VaultAuthContext
import java.io.ByteArrayOutputStream
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import javax.security.auth.x500.X500Principal

/** Authenticated SQJ anchor signing with a non-exportable Android Keystore P-256 key. */
public class AndroidJournalAnchorSigner(
    private val authVerifier: VaultAuthContextVerifier,
) : JournalAnchorSigner {

    override fun signCommittedDigest(
        sequence: Long,
        digestHex: String,
        authContext: VaultAuthContext,
    ): JournalSignatureAnchor {
        if (sequence <= 0L || !digestHex.matches(Regex("[0-9a-f]{64}"))) {
            throw VaultKeyAccessException(VaultKeyAccessFailure.INVALID_WRAP)
        }
        val now = SystemClock.elapsedRealtimeNanos()
        if (!authContext.validate(now) || !authVerifier.isCurrent(authContext) ||
            authContext.expiresAtMonotonicNs - now > AUTH_WINDOW_NANOS
        ) {
            throw VaultKeyAccessException(VaultKeyAccessFailure.AUTH_CONTEXT_INVALID)
        }

        val alias = currentAlias()
        val keyId = signingKeyId(publicKey(alias).encoded)
        try {
            val signer = Signature.getInstance(SIGNATURE_ALGORITHM)
            signer.initSign(privateKey(alias))
            signer.update(
                journalAnchorSigningPayload(
                    sequence,
                    digestHex,
                    keyId,
                    authContext.authorizationEpoch,
                    now,
                ),
            )
            val anchor = JournalSignatureAnchor(
                formatVersion = 1,
                sequence = sequence,
                digestHex = digestHex,
                signatureAlgorithmId = SIGNATURE_ID,
                signingKeyId = keyId,
                signatureBase64 = Base64.encodeToString(signer.sign(), Base64.NO_WRAP),
                authenticationEpoch = authContext.authorizationEpoch,
                monotonicTimestampNs = now,
            )
            if (!anchor.validate()) {
                throw VaultKeyAccessException(VaultKeyAccessFailure.CRYPTO_FAILURE)
            }
            return anchor
        } catch (e: UserNotAuthenticatedException) {
            throw VaultKeyAccessException(VaultKeyAccessFailure.AUTHENTICATION_REQUIRED, e)
        } catch (e: KeyPermanentlyInvalidatedException) {
            throw VaultKeyAccessException(VaultKeyAccessFailure.KEY_INVALIDATED, e)
        } catch (e: VaultKeyAccessException) {
            throw e
        } catch (e: Exception) {
            throw VaultKeyAccessException(VaultKeyAccessFailure.CRYPTO_FAILURE, e)
        }
    }

    /** Explicit rotation; retain old public keys for verification of prior anchors. */
    public fun rotateSigningKey(): String {
        val aliases = keyStore().aliases().toList().filter { it.startsWith(ALIAS_PREFIX) }
        val current = aliases.mapNotNull { it.removePrefix(ALIAS_PREFIX).toLongOrNull() }.maxOrNull() ?: 0L
        val alias = ALIAS_PREFIX + Math.addExact(current, 1L)
        generateSigningKey(alias)
        return signingKeyId(publicKey(alias).encoded)
    }

    public fun currentSigningPublicKeyBase64(): String =
        Base64.encodeToString(publicKey(currentAlias()).encoded, Base64.NO_WRAP)

    private fun currentAlias(): String {
        val aliases = keyStore().aliases().toList().filter { it.startsWith(ALIAS_PREFIX) }
        val newest = aliases.maxByOrNull { it.removePrefix(ALIAS_PREFIX).toLongOrNull() ?: -1L }
        if (newest != null) return newest
        val alias = ALIAS_PREFIX + "1"
        generateSigningKey(alias)
        return alias
    }

    private fun generateSigningKey(alias: String) {
        try {
            val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
            val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                builder.setUserAuthenticationParameters(
                    AUTH_WINDOW_SECONDS,
                    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                )
            } else {
                @Suppress("DEPRECATION")
                builder.setUserAuthenticationValidityDurationSeconds(AUTH_WINDOW_SECONDS)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                builder.setInvalidatedByBiometricEnrollment(true)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                builder.setUnlockedDeviceRequired(true)
            }
            builder.setCertificateSubject(X500Principal("CN=SQRecorder Journal Anchor"))
            generator.initialize(builder.build())
            generator.generateKeyPair()
        } catch (e: Exception) {
            throw VaultKeyAccessException(VaultKeyAccessFailure.CRYPTO_FAILURE, e)
        }
    }

    private fun privateKey(alias: String): PrivateKey {
        try {
            return keyStore().getKey(alias, null) as? PrivateKey
                ?: throw VaultKeyAccessException(VaultKeyAccessFailure.KEY_NOT_FOUND)
        } catch (e: KeyPermanentlyInvalidatedException) {
            throw VaultKeyAccessException(VaultKeyAccessFailure.KEY_INVALIDATED, e)
        } catch (e: VaultKeyAccessException) {
            throw e
        } catch (e: Exception) {
            throw VaultKeyAccessException(VaultKeyAccessFailure.CRYPTO_FAILURE, e)
        }
    }

    private fun publicKey(alias: String) =
        keyStore().getCertificate(alias)?.publicKey
            ?: throw VaultKeyAccessException(VaultKeyAccessFailure.KEY_NOT_FOUND)

    private fun keyStore(): KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val ALIAS_PREFIX = "sqrec.journal.ecdsa-p256-sha256.v1."
        const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
        const val SIGNATURE_ID = "ecdsa-p256-sha256-v1"
        const val AUTH_WINDOW_SECONDS = 30
        const val AUTH_WINDOW_NANOS = AUTH_WINDOW_SECONDS * 1_000_000_000L
    }
}

/** Binary, domain-separated anchor preimage; mirrored by the Rust verifier. */
internal fun journalAnchorSigningPayload(
    sequence: Long,
    digestHex: String,
    signingKeyId: String,
    authEpoch: Long,
    monotonicTimestampNs: Long,
): ByteArray {
    require(sequence > 0L && digestHex.matches(Regex("[0-9a-f]{64}")))
    require(signingKeyId.isNotBlank() && authEpoch >= 0L && monotonicTimestampNs >= 0L)
    val keyIdBytes = signingKeyId.toByteArray(Charsets.UTF_8)
    require(keyIdBytes.size <= 0xFFFF)
    val out = ByteArrayOutputStream()
    out.write("SQREC-JOURNAL-ANCHOR-V1".toByteArray(Charsets.US_ASCII))
    out.write(sequence.toLeBytes())
    out.write(digestHex.hexToBytes())
    out.write(keyIdBytes.size.toShort().toLeBytes())
    out.write(keyIdBytes)
    out.write(authEpoch.toLeBytes())
    out.write(monotonicTimestampNs.toLeBytes())
    return out.toByteArray()
}

internal fun signingKeyId(publicKeyDer: ByteArray): String {
    val digest = MessageDigest.getInstance("SHA-256").digest(publicKeyDer)
    val fingerprint = digest.take(16).joinToString("") { "%02x".format(it) }
    return "ecdsa-p256-sha256-v1-$fingerprint"
}

private fun Long.toLeBytes(): ByteArray =
    ByteArray(8) { index -> (this ushr (index * 8)).toByte() }

private fun Short.toLeBytes(): ByteArray =
    byteArrayOf(toInt().toByte(), (toInt() ushr 8).toByte())

private fun String.hexToBytes(): ByteArray =
    chunked(2).map { it.toInt(16).toByte() }.toByteArray()
