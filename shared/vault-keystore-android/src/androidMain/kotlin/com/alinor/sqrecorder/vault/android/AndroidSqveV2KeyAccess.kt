package com.alinor.sqrecorder.vault.android

import android.os.Build
import android.os.SystemClock
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import com.alinor.sqrecorder.domain.VaultAuthContext
import com.alinor.sqrecorder.domain.VaultFileKeyHandle
import com.alinor.sqrecorder.domain.VaultV2KeyAccess
import com.alinor.sqrecorder.domain.VaultV2RecipientWrap
import com.alinor.sqrecorder.domain.VaultV2WrapSuite
import java.io.ByteArrayOutputStream
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec

/**
 * V2-only ECDH-P256/HKDF-SHA256/AES-256-GCM recipient wrapping.
 * It never calls the V1 OAEP path or substitutes cryptographic parameters.
 * API 31+ uses non-exportable Android Keystore ECDH; API 23–30 uses the
 * separately identified RSA-3072 OAEP/MGF1-SHA1 compatibility suite.
 */
public class AndroidSqveV2KeyAccess(
    private val native: VaultNativeKeyBridge,
    private val authVerifier: VaultAuthContextVerifier,
) : VaultV2KeyAccess {
    override fun createRandomV2FileKeyHandle(): VaultFileKeyHandle =
        native.generateFileKeyHandle()

    override fun currentPublicV2RecipientKeyId(): String {
        requireV2Platform()
        val alias = if (Build.VERSION.SDK_INT < ECDH_API) currentRsaAlias(true) else currentAlias(true)
        return keyId(publicKey(alias), alias)
    }

    /** Rotate explicitly; old aliases remain available to decrypt prior files. */
    public fun rotateV2RecipientKey(): String {
        requireV2Platform()
        val alias = if (Build.VERSION.SDK_INT < ECDH_API) {
            RSA_ALIAS_PREFIX + Math.addExact(currentRsaVersion(), 1L)
        } else {
            ALIAS_PREFIX + Math.addExact(currentVersion(), 1L)
        }
        if (alias.startsWith(RSA_ALIAS_PREFIX)) generateRsaRecipientKey(alias) else generateRecipientKey(alias)
        return keyId(publicKey(alias), alias)
    }

    override fun wrapFileKeyForV2(
        fileKeyHandle: VaultFileKeyHandle,
        recipientKeyId: String,
        fileId: ByteArray,
        fileSalt: ByteArray,
    ): VaultV2RecipientWrap {
        requireV2Platform()
        validateFileContext(fileId, fileSalt)
        if (!recipientKeyId.isAsciiSafeId()) {
            throw VaultKeyAccessException(VaultKeyAccessFailure.INVALID_WRAP)
        }
        val recipientAlias = aliasForKeyId(recipientKeyId)
        val recipientPublic = publicKey(recipientAlias)
        if (recipientAlias.startsWith(RSA_ALIAS_PREFIX)) {
            return wrapFileKeyWithRsaV2(fileKeyHandle, recipientKeyId, recipientPublic)
        }
        val ephemeral = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC).apply {
            initialize(ECGenParameterSpec(CURVE), SecureRandom())
        }.generateKeyPair()
        val ephemeralDer = ephemeral.public.encoded
        val idBytes = recipientKeyId.toByteArray(Charsets.US_ASCII)
        val dek = native.copyFileKeyForWrapping(fileKeyHandle)
        var shared: ByteArray? = null
        var kek: ByteArray? = null
        val nonce = ByteArray(NONCE_BYTES).also(SecureRandom()::nextBytes)
        var ciphertextAndTag: ByteArray? = null
        try {
            if (dek.size != DEK_BYTES) {
                throw VaultKeyAccessException(VaultKeyAccessFailure.NATIVE_BRIDGE_FAILURE)
            }
            val sharedSecret = agree(ephemeral.private, recipientPublic, androidKeyStore = false)
            shared = sharedSecret
            kek = deriveKek(sharedSecret, fileSalt, fileId, idBytes)
            val cipher = Cipher.getInstance(AES_GCM)
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(kek, AES_KEY), GCMParameterSpec(TAG_BITS, nonce))
            cipher.updateAAD(wrapAad(fileId, idBytes, ephemeralDer))
            ciphertextAndTag = cipher.doFinal(dek)
            val canonicalPayload = encodeCanonicalEcdhPayload(ephemeralDer, nonce, ciphertextAndTag)
            try {
                return VaultV2RecipientWrap(
                    suite = VaultV2WrapSuite.ECDH_P256_HKDF_SHA256_AES256_GCM,
                    recipientKeyId = recipientKeyId,
                    wrappedDekBase64 = SqveBase64.encodeNoWrap(canonicalPayload),
                    ephemeralPublicKeyBase64 = SqveBase64.encodeNoWrap(ephemeralDer),
                    wrapNonceHex = nonce.toHex(),
                )
            } finally {
                canonicalPayload.fill(0)
            }
        } catch (e: VaultKeyAccessException) {
            throw e
        } catch (e: Exception) {
            throw VaultKeyAccessException(VaultKeyAccessFailure.CRYPTO_FAILURE, e)
        } finally {
            shared?.fill(0)
            kek?.fill(0)
            dek.fill(0)
            nonce.fill(0)
            ciphertextAndTag?.fill(0)
        }
    }

    override fun unwrapV2RecipientFileKey(
        wrap: VaultV2RecipientWrap,
        fileId: ByteArray,
        fileSalt: ByteArray,
        authContext: VaultAuthContext,
    ): VaultFileKeyHandle {
        requireV2Platform()
        validateFileContext(fileId, fileSalt)
        if (!wrap.recipientKeyId.isAsciiSafeId()) {
            throw VaultKeyAccessException(VaultKeyAccessFailure.INVALID_WRAP)
        }
        val now = SystemClock.elapsedRealtimeNanos()
        if (!isCurrentVaultAuthContext(authContext, now, authVerifier)) {
            throw VaultKeyAccessException(VaultKeyAccessFailure.AUTH_CONTEXT_INVALID)
        }
        val alias = aliasForKeyId(wrap.recipientKeyId)
        if (wrap.suite == VaultV2WrapSuite.RSA3072_OAEP_SHA256_MGF1_SHA1_EMPTY_LABEL) {
            if (!alias.startsWith(RSA_ALIAS_PREFIX) || wrap.ephemeralPublicKeyBase64 != null ||
                wrap.wrapNonceHex != null
            ) throw VaultKeyAccessException(VaultKeyAccessFailure.INVALID_WRAP)
            return unwrapRsaV2(wrap, alias)
        }
        if (wrap.suite != VaultV2WrapSuite.ECDH_P256_HKDF_SHA256_AES256_GCM ||
            alias.startsWith(RSA_ALIAS_PREFIX)
        ) throw VaultKeyAccessException(VaultKeyAccessFailure.UNSUPPORTED_PLATFORM)
        val ephemeralBase64 = wrap.ephemeralPublicKeyBase64
            ?: throw VaultKeyAccessException(VaultKeyAccessFailure.INVALID_WRAP)
        val nonceHex = wrap.wrapNonceHex
            ?: throw VaultKeyAccessException(VaultKeyAccessFailure.INVALID_WRAP)
        if (!nonceHex.isLowerHex(NONCE_BYTES * 2)) {
            throw VaultKeyAccessException(VaultKeyAccessFailure.INVALID_WRAP)
        }
        val canonicalPayload = decodeCanonicalBase64(wrap.wrappedDekBase64)
        val parsed = try {
            parseCanonicalEcdhPayload(canonicalPayload)
        } catch (e: Exception) {
            canonicalPayload.fill(0)
            throw e
        }
        val ephemeralDer = parsed.ephemeralDer
        val ciphertextAndTag = parsed.ciphertextAndTag
        val nonce = parsed.nonce
        val separatelyEncodedEphemeral = decodeCanonicalBase64(ephemeralBase64)
        val separatelyEncodedNonce = nonceHex.hexToBytes()
        if (ephemeralDer.size !in MIN_SPKI_BYTES..MAX_SPKI_BYTES ||
            !ephemeralDer.contentEquals(separatelyEncodedEphemeral) ||
            !nonce.contentEquals(separatelyEncodedNonce)
        ) {
            canonicalPayload.fill(0)
            ephemeralDer.fill(0)
            ciphertextAndTag.fill(0)
            nonce.fill(0)
            separatelyEncodedEphemeral.fill(0)
            separatelyEncodedNonce.fill(0)
            throw VaultKeyAccessException(VaultKeyAccessFailure.INVALID_WRAP)
        }
        separatelyEncodedEphemeral.fill(0)
        separatelyEncodedNonce.fill(0)

        var shared: ByteArray? = null
        var kek: ByteArray? = null
        var dek: ByteArray? = null
        try {
            val ephemeralPublic = KeyFactory.getInstance("EC")
                .generatePublic(X509EncodedKeySpec(ephemeralDer))
            val ecPublic = ephemeralPublic as? java.security.interfaces.ECPublicKey
            if (ecPublic?.params?.curve?.field?.fieldSize != 256 ||
                !ephemeralPublic.encoded.contentEquals(ephemeralDer)
            ) throw VaultKeyAccessException(VaultKeyAccessFailure.INVALID_WRAP)

            val privateKey = keyStore().getKey(alias, null) as? java.security.PrivateKey
                ?: throw VaultKeyAccessException(VaultKeyAccessFailure.KEY_NOT_FOUND)
            shared = agree(privateKey, ephemeralPublic, androidKeyStore = true)
            val idBytes = wrap.recipientKeyId.toByteArray(Charsets.US_ASCII)
            kek = deriveKek(shared, fileSalt, fileId, idBytes)
            val cipher = Cipher.getInstance(AES_GCM)
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(kek, AES_KEY), GCMParameterSpec(TAG_BITS, nonce))
            cipher.updateAAD(wrapAad(fileId, idBytes, ephemeralDer))
            dek = cipher.doFinal(ciphertextAndTag)
            if (dek.size != DEK_BYTES) throw VaultKeyAccessException(VaultKeyAccessFailure.INVALID_WRAP)
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
            canonicalPayload.fill(0)
            ephemeralDer.fill(0)
            ciphertextAndTag.fill(0)
            nonce.fill(0)
            shared?.fill(0)
            kek?.fill(0)
            dek?.fill(0)
        }
    }

    private fun wrapFileKeyWithRsaV2(
        handle: VaultFileKeyHandle,
        recipientKeyId: String,
        recipientPublic: PublicKey,
    ): VaultV2RecipientWrap {
        val dek = native.copyFileKeyForWrapping(handle)
        try {
            if (dek.size != DEK_BYTES) {
                throw VaultKeyAccessException(VaultKeyAccessFailure.NATIVE_BRIDGE_FAILURE)
            }
            val cipher = Cipher.getInstance(RSA_OAEP_TRANSFORMATION, ANDROID_KEYSTORE)
            cipher.init(Cipher.ENCRYPT_MODE, recipientPublic, RSA3072_OAEP_SPEC)
            val wrapped = cipher.doFinal(dek)
            try {
                if (wrapped.size != RSA3072_CIPHERTEXT_BYTES) {
                    throw VaultKeyAccessException(VaultKeyAccessFailure.INVALID_WRAP)
                }
                return VaultV2RecipientWrap(
                    suite = VaultV2WrapSuite.RSA3072_OAEP_SHA256_MGF1_SHA1_EMPTY_LABEL,
                    recipientKeyId = recipientKeyId,
                    wrappedDekBase64 = SqveBase64.encodeNoWrap(wrapped),
                )
            } finally {
                wrapped.fill(0)
            }
        } catch (e: VaultKeyAccessException) {
            throw e
        } catch (e: Exception) {
            throw VaultKeyAccessException(VaultKeyAccessFailure.CRYPTO_FAILURE, e)
        } finally {
            dek.fill(0)
        }
    }

    private fun unwrapRsaV2(wrap: VaultV2RecipientWrap, alias: String): VaultFileKeyHandle {
        val ciphertext = decodeCanonicalBase64(wrap.wrappedDekBase64)
        if (ciphertext.size != RSA3072_CIPHERTEXT_BYTES) {
            ciphertext.fill(0)
            throw VaultKeyAccessException(VaultKeyAccessFailure.INVALID_WRAP)
        }
        var dek: ByteArray? = null
        try {
            val privateKey = keyStore().getKey(alias, null) as? java.security.PrivateKey
                ?: throw VaultKeyAccessException(VaultKeyAccessFailure.KEY_NOT_FOUND)
            val cipher = Cipher.getInstance(RSA_OAEP_TRANSFORMATION, ANDROID_KEYSTORE)
            cipher.init(Cipher.DECRYPT_MODE, privateKey, RSA3072_OAEP_SPEC)
            dek = cipher.doFinal(ciphertext)
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
            ciphertext.fill(0)
            dek?.fill(0)
        }
    }

    private fun requireV2Platform() {
        if (Build.VERSION.SDK_INT < MIN_V2_API) {
            throw VaultKeyAccessException(VaultKeyAccessFailure.UNSUPPORTED_PLATFORM)
        }
    }

    private fun currentAlias(createIfMissing: Boolean): String {
        val aliases = keyStore().aliases().toList().filter { it.startsWith(ALIAS_PREFIX) }
        val newest = aliases.maxByOrNull { it.removePrefix(ALIAS_PREFIX).toLongOrNull() ?: -1L }
        if (newest != null) return newest
        if (!createIfMissing) throw VaultKeyAccessException(VaultKeyAccessFailure.KEY_NOT_FOUND)
        val alias = ALIAS_PREFIX + "1"
        generateRecipientKey(alias)
        return alias
    }

    private fun currentVersion(): Long =
        keyStore().aliases().toList().filter { it.startsWith(ALIAS_PREFIX) }
            .mapNotNull { it.removePrefix(ALIAS_PREFIX).toLongOrNull() }.maxOrNull() ?: 0L

    private fun currentRsaAlias(createIfMissing: Boolean): String {
        val aliases = keyStore().aliases().toList().filter { it.startsWith(RSA_ALIAS_PREFIX) }
        val newest = aliases.maxByOrNull { it.removePrefix(RSA_ALIAS_PREFIX).toLongOrNull() ?: -1L }
        if (newest != null) return newest
        if (!createIfMissing) throw VaultKeyAccessException(VaultKeyAccessFailure.KEY_NOT_FOUND)
        val alias = RSA_ALIAS_PREFIX + "1"
        generateRsaRecipientKey(alias)
        return alias
    }

    private fun currentRsaVersion(): Long =
        keyStore().aliases().toList().filter { it.startsWith(RSA_ALIAS_PREFIX) }
            .mapNotNull { it.removePrefix(RSA_ALIAS_PREFIX).toLongOrNull() }.maxOrNull() ?: 0L

    private fun generateRecipientKey(alias: String) {
        try {
            val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_AGREE_KEY)
                .setAlgorithmParameterSpec(ECGenParameterSpec(CURVE))
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
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) builder.setUnlockedDeviceRequired(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                builder.setInvalidatedByBiometricEnrollment(true)
            }
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).apply {
                initialize(builder.build())
            }.generateKeyPair()
        } catch (e: Exception) {
            throw VaultKeyAccessException(VaultKeyAccessFailure.CRYPTO_FAILURE, e)
        }
    }

    private fun generateRsaRecipientKey(alias: String) {
        try {
            val builder = KeyGenParameterSpec.Builder(
                alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setKeySize(RSA3072_BITS)
                .setDigests(KeyProperties.DIGEST_SHA256)
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
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) builder.setUnlockedDeviceRequired(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                builder.setInvalidatedByBiometricEnrollment(true)
            }
            if (Build.VERSION.SDK_INT >= 35) {
                builder.setMgf1Digests(KeyProperties.DIGEST_SHA1)
            }
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE).apply {
                initialize(builder.build())
            }.generateKeyPair()
        } catch (e: Exception) {
            throw VaultKeyAccessException(VaultKeyAccessFailure.CRYPTO_FAILURE, e)
        }
    }

    private fun publicKey(alias: String): PublicKey =
        keyStore().getCertificate(alias)?.publicKey
            ?: throw VaultKeyAccessException(VaultKeyAccessFailure.KEY_NOT_FOUND)

    private fun aliasForKeyId(id: String): String {
        val store = keyStore()
        return store.aliases().toList().firstOrNull { alias ->
            (alias.startsWith(ALIAS_PREFIX) || alias.startsWith(RSA_ALIAS_PREFIX)) &&
                store.getCertificate(alias)?.publicKey?.let { keyId(it, alias) } == id
        } ?: throw VaultKeyAccessException(VaultKeyAccessFailure.KEY_NOT_FOUND)
    }

    private fun keyId(publicKey: PublicKey, alias: String): String {
        val prefix = if (alias.startsWith(RSA_ALIAS_PREFIX)) {
            "android-v2-rsa3072-oaep256-mgf1sha1-"
        } else {
            "android-v2-ecdh-"
        }
        return prefix + MessageDigest.getInstance("SHA-256").digest(publicKey.encoded).toHex()
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val ALIAS_PREFIX = "sqrec.vault.sqve2.ecdh-p256.v2."
        const val CURVE = "secp256r1"
        const val MIN_V2_API = 23
        const val ECDH_API = 31
        const val RSA_ALIAS_PREFIX = "sqrec.vault.sqve2.rsa3072.v3."
        const val RSA3072_CIPHERTEXT_BYTES = 384
        const val RSA3072_BITS = 3072
        const val RSA_OAEP_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
        val RSA3072_OAEP_SPEC = OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT,
        )
        const val AUTH_WINDOW_SECONDS = 30
        const val DEK_BYTES = 32
        const val NONCE_BYTES = 12
        const val TAG_BYTES = 16
        const val TAG_BITS = 128
        const val MIN_SPKI_BYTES = 64
        const val MAX_SPKI_BYTES = 512
        const val AES_KEY = "AES"
        const val AES_GCM = "AES/GCM/NoPadding"
    }
}

private data class ParsedCanonicalEcdhPayload(
    val ephemeralDer: ByteArray,
    val nonce: ByteArray,
    val ciphertextAndTag: ByteArray,
)

private fun encodeCanonicalEcdhPayload(
    ephemeralDer: ByteArray,
    nonce: ByteArray,
    ciphertextAndTag: ByteArray,
): ByteArray {
    require(ephemeralDer.isNotEmpty() && ephemeralDer.size <= 2_048)
    require(nonce.size == 12 && ciphertextAndTag.size == 48)
    return ByteArrayOutputStream().apply {
        write(u16be(ephemeralDer.size))
        write(ephemeralDer)
        write(nonce)
        write(ciphertextAndTag)
    }.toByteArray()
}

private fun parseCanonicalEcdhPayload(bytes: ByteArray): ParsedCanonicalEcdhPayload {
    if (bytes.size < 63 || bytes.size > 8_192) {
        throw VaultKeyAccessException(VaultKeyAccessFailure.INVALID_WRAP)
    }
    val derLength = ((bytes[0].toInt() and 0xff) shl 8) or (bytes[1].toInt() and 0xff)
    if (derLength !in 1..2_048) {
        throw VaultKeyAccessException(VaultKeyAccessFailure.INVALID_WRAP)
    }
    val nonceAt = 2 + derLength
    val cipherAt = nonceAt + 12
    val end = cipherAt + 32 + 16
    if (end != bytes.size) {
        throw VaultKeyAccessException(VaultKeyAccessFailure.INVALID_WRAP)
    }
    return ParsedCanonicalEcdhPayload(
        ephemeralDer = bytes.copyOfRange(2, nonceAt),
        nonce = bytes.copyOfRange(nonceAt, cipherAt),
        ciphertextAndTag = bytes.copyOfRange(cipherAt, end),
    )
}

private fun agree(
    privateKey: java.security.PrivateKey,
    peer: PublicKey,
    androidKeyStore: Boolean,
): ByteArray {
    val agreement = if (androidKeyStore) KeyAgreement.getInstance("ECDH", "AndroidKeyStore")
    else KeyAgreement.getInstance("ECDH")
    agreement.init(privateKey)
    agreement.doPhase(peer, true)
    return agreement.generateSecret()
}

private fun deriveKek(
    sharedSecret: ByteArray,
    salt: ByteArray,
    fileId: ByteArray,
    recipientId: ByteArray,
): ByteArray {
    val prk = hmacSha256(salt, sharedSecret)
    val info = ByteArrayOutputStream().apply {
        write("SQREC-SQVE2-ECDH-P256-DEK-WRAP-v1".toByteArray(Charsets.US_ASCII))
        write(fileId)
        write(u16be(recipientId.size))
        write(recipientId)
    }.toByteArray()
    return try {
        hmacSha256(prk, info + byteArrayOf(1))
    } finally {
        prk.fill(0)
        info.fill(0)
    }
}

private fun wrapAad(fileId: ByteArray, recipientId: ByteArray, ephemeralDer: ByteArray): ByteArray =
    ByteArrayOutputStream().apply {
        write(u16be(0x0002))
        write(fileId)
        write(u16be(recipientId.size))
        write(recipientId)
        write(ephemeralDer)
    }.toByteArray()

private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray =
    Mac.getInstance("HmacSHA256").run {
        init(SecretKeySpec(key, "HmacSHA256"))
        doFinal(data)
    }

private fun u16be(value: Int): ByteArray =
    byteArrayOf((value ushr 8).toByte(), value.toByte())

private fun ByteArray.toHex(): String =
    joinToString("") { "%02x".format(it.toInt() and 0xff) }

private fun String.hexToBytes(): ByteArray =
    ByteArray(length / 2) { i -> substring(i * 2, i * 2 + 2).toInt(16).toByte() }

private fun String.isLowerHex(expectedLength: Int): Boolean =
    length == expectedLength && all { it in '0'..'9' || it in 'a'..'f' }

private fun String.isAsciiSafeId(): Boolean =
    isNotEmpty() && length <= 128 && all {
        it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' ||
            it == '.' || it == '_' || it == '-' || it == ':'
    }

private fun validateFileContext(fileId: ByteArray, fileSalt: ByteArray) {
    if (fileId.size != 16 || fileSalt.size != 32) {
        throw VaultKeyAccessException(VaultKeyAccessFailure.INVALID_WRAP)
    }
}

private fun decodeCanonicalBase64(value: String): ByteArray {
    val bytes = try {
        SqveBase64.decodeCanonical(value)
    } catch (e: IllegalArgumentException) {
        throw VaultKeyAccessException(VaultKeyAccessFailure.INVALID_WRAP, e)
    }
    if (SqveBase64.encodeNoWrap(bytes) != value) {
        bytes.fill(0)
        throw VaultKeyAccessException(VaultKeyAccessFailure.INVALID_WRAP)
    }
    return bytes
}
