package com.alinor.sqrecorder.vault.android

import java.security.KeyStore

/**
 * Resolves anchor verification keys from Android Keystore's retained signing aliases.
 *
 * Rotation creates a new numbered alias; existing aliases are deliberately not deleted.
 * Public keys are derived from Keystore certificates, never from the active alias alone.
 * A missing/corrupt historical key fails closed as KEY_NOT_FOUND at verifier level.
 */
public class AndroidKeystoreJournalAnchorPublicKeyResolver(
    private val keyStoreProvider: () -> KeyStore = {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    },
) : JournalAnchorPublicKeyResolver {
    override fun resolveEncodedPublicKey(keyId: String): ByteArray? {
        if (!keyId.matches(Regex("ecdsa-p256-sha256-v1-[0-9a-f]{32}"))) return null
        return try {
            val store = keyStoreProvider()
            val retained = store.aliases().toList()
                .filter { it.startsWith(SIGNING_ALIAS_PREFIX) }
                .mapNotNull { alias -> store.getCertificate(alias)?.publicKey?.encoded }
            resolveRetainedAnchorPublicKey(keyId, retained)
        } catch (_: Exception) {
            null // Never substitute current key when retained-key lookup fails.
        }
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val SIGNING_ALIAS_PREFIX = "sqrec.journal.ecdsa-p256-sha256.v1."
    }
}

/** Pure selector used by the Keystore resolver and host contract tests. */
internal fun resolveRetainedAnchorPublicKey(
    keyId: String,
    retainedEncodedPublicKeys: List<ByteArray>,
): ByteArray? {
    if (!keyId.matches(Regex("ecdsa-p256-sha256-v1-[0-9a-f]{32}"))) return null
    return retainedEncodedPublicKeys.firstOrNull { publicKeyId(it) == keyId }?.copyOf()
}
