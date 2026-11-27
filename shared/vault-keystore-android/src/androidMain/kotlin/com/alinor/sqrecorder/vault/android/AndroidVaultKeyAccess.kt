package com.alinor.sqrecorder.vault.android

import android.os.Build
import android.os.SystemClock
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import android.util.Base64
import com.alinor.sqrecorder.domain.VaultAuthContext
import com.alinor.sqrecorder.domain.VaultChunkCipher
import com.alinor.sqrecorder.domain.VaultFileKeyHandle
import com.alinor.sqrecorder.domain.VaultKeyAccess
import com.alinor.sqrecorder.domain.VaultKeyWrap
import com.alinor.sqrecorder.domain.VaultKeyWrapSuite
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.security.auth.x500.X500Principal

/** The native bridge retains the DEK in Rust-owned zeroizing memory. */
public interface VaultNativeKeyBridge {
    public fun generateFileKeyHandle(): VaultFileKeyHandle
    /** A transient 32-byte copy, zeroized by the caller immediately after wrap. */
    public fun copyFileKeyForWrapping(handle: VaultFileKeyHandle): ByteArray
    /** Copies the authenticated DEK into Rust-owned memory; caller clears its input. */
    public fun importUnwrappedFileKey(dek: ByteArray): VaultFileKeyHandle
    public fun encryptChunk(
        handle: VaultFileKeyHandle,
        nonce: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
    ): ByteArray
    public fun decryptChunk(
        handle: VaultFileKeyHandle,
        nonce: ByteArray,
        aad: ByteArray,
        ciphertextAndTag: ByteArray,
    ): ByteArray
}

public fun interface VaultAuthContextVerifier {
    /** Must reject revoked sessions/epochs, not merely trust the caller's expiry. */
    public fun isCurrent(context: VaultAuthContext): Boolean
}

internal val SQVE_V1_OAEP_LABEL = "SQREC-VAULT-DEK-v1".toByteArray(Charsets.UTF_8)

internal fun androidKeystoreSupportsSqveV1Oaep(apiLevel: Int): Boolean =
    apiLevel >= 35 && SQVE_V1_OAEP_LABEL.isEmpty()

public enum class VaultKeyAccessFailure {
    AUTHENTICATION_REQUIRED,
    AUTH_CONTEXT_INVALID,
    KEY_INVALIDATED,
    KEY_NOT_FOUND,
    INVALID_WRAP,
    CRYPTO_FAILURE,
    NATIVE_BRIDGE_FAILURE,
    UNSUPPORTED_PLATFORM,
}

public class VaultKeyAccessException(
    public val failure: VaultKeyAccessFailure,
    cause: Throwable? = null,
) : Exception(failure.name, cause)

/**
 * Android RSA-OAEP key custody for locked SQVE v1.
 * Public-key wrapping is available in encrypt-only/locked capture. Private-key
 * unwrap is protected by Android Keystore auth and the app's revocable auth epoch.
 * Rotation is explicit; invalidated aliases are never silently replaced.
 */
public class AndroidVaultKeyAccess(
    private val native: VaultNativeKeyBridge,
    private val authVerifier: VaultAuthContextVerifier,
) : VaultKeyAccess {

    override fun createRandomFileKeyHandle(): VaultFileKeyHandle =
        native.generateFileKeyHandle()

    override fun currentPublicWrappingKeyId(): String {
        requireSqveV1AndroidKeystoreSupport()
        return vaultWrappingKeyId(publicKeyForAlias(currentAlias(createIfMissing = true)))
    }

    override fun wrapFileKeyWithPublicKey(
        fileKeyHandle: VaultFileKeyHandle,
        recipientKeyId: String,
    ): VaultKeyWrap {
        requireSqveV1AndroidKeystoreSupport()
        val publicKey = publicKeyForAlias(aliasForKeyId(recipientKeyId))
        val dek = native.copyFileKeyForWrapping(fileKeyHandle)
        try {
            if (dek.size != DEK_BYTES) {
                throw VaultKeyAccessException(VaultKeyAccessFailure.NATIVE_BRIDGE_FAILURE)
            }
            val cipher = Cipher.getInstance(OAEP_TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, publicKey, vaultOaepParameters())
            val wrapped = cipher.doFinal(dek)
            return VaultKeyWrap(
                suite = VaultKeyWrapSuite.RSA_OAEP_SHA256_V1,
                recipientKeyId = recipientKeyId,
                wrappedFileKeyBase64 = Base64.encodeToString(wrapped, Base64.NO_WRAP),
            )
        } catch (e: VaultKeyAccessException) {
            throw e
        } catch (e: Exception) {
            throw VaultKeyAccessException(VaultKeyAccessFailure.CRYPTO_FAILURE, e)
        } finally {
            dek.fill(0)
        }
    }

    override fun unwrapFileKeyWithPrivateKey(
        wrap: VaultKeyWrap,
        authContext: VaultAuthContext,
    ): VaultFileKeyHandle {
        if (wrap.suite != VaultKeyWrapSuite.RSA_OAEP_SHA256_V1) {
            throw VaultKeyAccessException(VaultKeyAccessFailure.INVALID_WRAP)
        }
        requireSqveV1AndroidKeystoreSupport()
        val now = SystemClock.elapsedRealtimeNanos()
        if (!authContext.validate(now) || !authVerifier.isCurrent(authContext) ||
            authContext.expiresAtMonotonicNs - now > AUTH_WINDOW_NANOS
        ) {
            throw VaultKeyAccessException(VaultKeyAccessFailure.AUTH_CONTEXT_INVALID)
        }

        val alias = aliasForKeyId(wrap.recipientKeyId)
        val wrappedBytes = try {
            Base64.decode(wrap.wrappedFileKeyBase64, Base64.NO_WRAP)
        } catch (e: IllegalArgumentException) {
            throw VaultKeyAccessException(VaultKeyAccessFailure.INVALID_WRAP, e)
        }
        if (Base64.encodeToString(wrappedBytes, Base64.NO_WRAP) != wrap.wrappedFileKeyBase64) {
            wrappedBytes.fill(0)
            throw VaultKeyAccessException(VaultKeyAccessFailure.INVALID_WRAP)
        }

        var dek: ByteArray? = null
        try {
            val privateKey = privateKeyForAlias(alias)
            val cipher = Cipher.getInstance(OAEP_TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, privateKey, vaultOaepParameters())
            dek = cipher.doFinal(wrappedBytes)
            if (dek.size != DEK_BYTES) {
                throw VaultKeyAccessException(VaultKeyAccessFailure.INVALID_WRAP)
            }
            return native.importUnwrappedFileKey(dek)
        } catch (e: UserNotAuthenticatedException) {
            throw VaultKeyAccessException(VaultKeyAccessFailure.AUTHENTICATION_REQUIRED, e)
        } catch (e: KeyPermanentlyInvalidatedException) {
            throw VaultKeyAccessException(VaultKeyAccessFailure.KEY_INVALIDATED, e)
        } catch (e: VaultKeyAccessException) {
            throw e
        } catch (e: Exception) {
            throw VaultKeyAccessException(VaultKeyAccessFailure.CRYPTO_FAILURE, e)
        } finally {
            wrappedBytes.fill(0)
            dek?.fill(0)
        }
    }

    /** Explicit rotation. Old aliases remain available for historical files. */
    public fun rotateWrappingKey(): String {
        requireSqveV1AndroidKeystoreSupport()
        val aliases = keyStore().aliases().toList().filter { it.startsWith(ALIAS_PREFIX) }
        val current = aliases.mapNotNull { it.removePrefix(ALIAS_PREFIX).toLongOrNull() }.maxOrNull() ?: 0L
        val next = Math.addExact(current, 1L)
        val alias = ALIAS_PREFIX + next
        generateWrappingKey(alias)
        return vaultWrappingKeyId(publicKeyForAlias(alias))
    }

    private fun requireSqveV1AndroidKeystoreSupport() {
        if (!androidKeystoreSupportsSqveV1Oaep(Build.VERSION.SDK_INT)) {
            throw VaultKeyAccessException(VaultKeyAccessFailure.UNSUPPORTED_PLATFORM)
        }
    }

    private fun currentAlias(createIfMissing: Boolean): String {
        val aliases = keyStore().aliases().toList().filter { it.startsWith(ALIAS_PREFIX) }
        val newest = aliases.maxByOrNull { it.removePrefix(ALIAS_PREFIX).toLongOrNull() ?: -1L }
        if (newest != null) return newest
        if (!createIfMissing) throw VaultKeyAccessException(VaultKeyAccessFailure.KEY_NOT_FOUND)
        val alias = ALIAS_PREFIX + "1"
        generateWrappingKey(alias)
        return alias
    }

    private fun generateWrappingKey(alias: String) {
        // Android Keystore rejects non-empty OAEP PSource labels. SQVE v1 locks
        // a non-empty label, so never create an unusable key or silently change format.
        if (!androidKeystoreSupportsSqveV1Oaep(Build.VERSION.SDK_INT)) {
            throw VaultKeyAccessException(VaultKeyAccessFailure.UNSUPPORTED_PLATFORM)
        }
        // Android Keystore exposed configurable MGF1 digests in API 35.
        // SQVE v1 locks MGF1=SHA-256; never downgrade to the historical SHA-1 default.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.VANILLA_ICE_CREAM) {
            throw VaultKeyAccessException(VaultKeyAccessFailure.UNSUPPORTED_PLATFORM)
        }
        try {
            val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE)
            val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(RSA_KEY_BITS)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setMgf1Digests(KeyProperties.DIGEST_SHA256)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
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
            builder.setCertificateSubject(X500Principal("CN=SQRecorder Vault Wrapping"))
            generator.initialize(builder.build())
            generator.generateKeyPair()
        } catch (e: Exception) {
            throw VaultKeyAccessException(VaultKeyAccessFailure.CRYPTO_FAILURE, e)
        }
    }

    private fun publicKeyForAlias(alias: String): PublicKey {
        try {
            val certificate = keyStore().getCertificate(alias)
                ?: throw VaultKeyAccessException(VaultKeyAccessFailure.KEY_NOT_FOUND)
            return certificate.publicKey
        } catch (e: VaultKeyAccessException) {
            throw e
        } catch (e: Exception) {
            throw VaultKeyAccessException(VaultKeyAccessFailure.CRYPTO_FAILURE, e)
        }
    }

    private fun privateKeyForAlias(alias: String): PrivateKey {
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

    private fun aliasForKeyId(id: String): String {
        val store = keyStore()
        val alias = store.aliases().toList().firstOrNull { candidate ->
            candidate.startsWith(ALIAS_PREFIX) &&
                store.getCertificate(candidate)?.publicKey?.let(::vaultWrappingKeyId) == id
        }
        return alias ?: throw VaultKeyAccessException(VaultKeyAccessFailure.KEY_NOT_FOUND)
    }

    private fun keyStore(): KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val ALIAS_PREFIX = "sqrec.vault.rsa-oaep-sha256.v1."
        const val OAEP_TRANSFORMATION = "RSA/ECB/OAEPPadding"
        const val RSA_KEY_BITS = 3072
        const val DEK_BYTES = 32
        const val AUTH_WINDOW_SECONDS = 30
        const val AUTH_WINDOW_NANOS = AUTH_WINDOW_SECONDS * 1_000_000_000L
    }
}

/** Rust remains the chunk-AEAD provider; Android enforces the auth session boundary. */
public class AndroidVaultChunkCipher(
    private val native: VaultNativeKeyBridge,
    private val authVerifier: VaultAuthContextVerifier,
) : VaultChunkCipher {
    override fun encryptChunk(
        fileKeyHandle: VaultFileKeyHandle,
        nonce: ByteArray,
        associatedData: ByteArray,
        plaintext: ByteArray,
    ): ByteArray = native.encryptChunk(fileKeyHandle, nonce, associatedData, plaintext)

    override fun decryptChunk(
        fileKeyHandle: VaultFileKeyHandle,
        nonce: ByteArray,
        associatedData: ByteArray,
        ciphertextAndTag: ByteArray,
        authContext: VaultAuthContext,
    ): ByteArray {
        val now = SystemClock.elapsedRealtimeNanos()
        if (!authContext.validate(now) || !authVerifier.isCurrent(authContext)) {
            throw VaultKeyAccessException(VaultKeyAccessFailure.AUTH_CONTEXT_INVALID)
        }
        return native.decryptChunk(fileKeyHandle, nonce, associatedData, ciphertextAndTag)
    }
}

internal fun vaultOaepParameters(): OAEPParameterSpec = OAEPParameterSpec(
    "SHA-256",
    "MGF1",
    MGF1ParameterSpec.SHA256,
    PSource.PSpecified("SQREC-VAULT-DEK-v1".toByteArray(Charsets.UTF_8)),
)

internal fun vaultWrappingKeyId(publicKey: PublicKey): String {
    val digest = MessageDigest.getInstance("SHA-256").digest(publicKey.encoded)
    val fingerprint = digest.take(16).joinToString("") { "%02x".format(it) }
    return "rsa-oaep-sha256-v1-$fingerprint"
}
