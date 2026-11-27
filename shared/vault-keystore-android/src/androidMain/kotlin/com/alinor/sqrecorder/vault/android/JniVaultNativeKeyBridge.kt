package com.alinor.sqrecorder.vault.android

import com.alinor.sqrecorder.domain.VaultFileKeyHandle

/** JNI adapter for the stable sq_vault_* v1 C ABI. */
public class JniVaultNativeKeyBridge : VaultNativeKeyBridge {
    override fun generateFileKeyHandle(): VaultFileKeyHandle {
        val handle = nativeCreateFileKeyHandle()
        check(handle > 0L) { "native Vault key allocation failed" }
        return VaultFileKeyHandle(handle.toString())
    }

    override fun destroyFileKeyHandle(handle: VaultFileKeyHandle) {
        check(nativeDestroyFileKeyHandle(parseHandle(handle)) == STATUS_OK) {
            "native Vault key destroy failed"
        }
    }

    override fun copyFileKeyForWrapping(handle: VaultFileKeyHandle): ByteArray {
        val bytes = nativeCopyFileKeyForWrapping(parseHandle(handle))
        if (bytes.size != DEK_BYTES) {
            bytes.fill(0)
            error("native Vault wrap buffer has invalid length")
        }
        return bytes
    }

    override fun importUnwrappedFileKey(dek: ByteArray): VaultFileKeyHandle {
        try {
            val handle = nativeImportUnwrappedFileKey(dek)
            check(handle > 0L) { "native Vault DEK import failed" }
            return VaultFileKeyHandle(handle.toString())
        } finally {
            dek.fill(0)
        }
    }

    override fun encryptChunk(
        handle: VaultFileKeyHandle,
        nonce: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
    ): ByteArray {
        val result = nativeEncryptChunk(parseHandle(handle), nonce, aad, plaintext)
        if (result.size != plaintext.size + GCM_TAG_BYTES) {
            result.fill(0)
            error("native Vault ciphertext length mismatch")
        }
        return result
    }

    override fun decryptChunk(
        handle: VaultFileKeyHandle,
        nonce: ByteArray,
        aad: ByteArray,
        ciphertextAndTag: ByteArray,
    ): ByteArray {
        require(ciphertextAndTag.size >= GCM_TAG_BYTES)
        val result = nativeDecryptChunk(parseHandle(handle), nonce, aad, ciphertextAndTag)
        if (result.size != ciphertextAndTag.size - GCM_TAG_BYTES) {
            result.fill(0)
            error("native Vault plaintext length mismatch")
        }
        return result
    }

    private fun parseHandle(handle: VaultFileKeyHandle): Long =
        handle.opaqueId.toLongOrNull()?.takeIf { it > 0L }
            ?: error("invalid native Vault handle")

    private external fun nativeCreateFileKeyHandle(): Long
    private external fun nativeDestroyFileKeyHandle(handle: Long): Int
    private external fun nativeCopyFileKeyForWrapping(handle: Long): ByteArray
    private external fun nativeImportUnwrappedFileKey(dek: ByteArray): Long
    private external fun nativeEncryptChunk(
        handle: Long,
        nonce: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
    ): ByteArray
    private external fun nativeDecryptChunk(
        handle: Long,
        nonce: ByteArray,
        aad: ByteArray,
        ciphertextAndTag: ByteArray,
    ): ByteArray

    private companion object {
        const val STATUS_OK = 0
        const val DEK_BYTES = 32
        const val GCM_TAG_BYTES = 16

        init {
            System.loadLibrary("sqrec_native_abi")
        }
    }
}
