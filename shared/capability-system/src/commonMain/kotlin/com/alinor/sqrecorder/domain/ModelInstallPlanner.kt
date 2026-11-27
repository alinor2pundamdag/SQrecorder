package com.alinor.sqrecorder.domain

/**
 * Signed model catalog metadata. Cryptographic signature verification and publisher
 * trust-chain evaluation happen in the catalog/provider boundary; this common
 * contract consumes the resulting ModelTrust verdict and never downloads itself.
 */
public data class ModelArtifactManifest(
    public val schemaVersion: Int,
    public val modelId: String,
    public val version: SemanticVersion,
    public val artifactBytes: Long,
    public val sha256Hex: String,
    public val licenseId: String,
    public val provenance: String,
    public val runtimeApi: SemanticVersion,
    public val minimumEngineVersion: SemanticVersion,
    public val publisherKeyId: String,
    public val signatureBase64: String,
)

public enum class ModelTrust {
    VERIFIED,
    UNVERIFIED,
    REVOKED,
}

public enum class ModelInstallAction {
    INSTALL,
    DELETE_PARTIAL_AND_RESTART,
    ALREADY_INSTALLED,
    REJECT,
}

public enum class ModelInstallReason {
    INVALID_MANIFEST,
    MANIFEST_UNTRUSTED,
    INSUFFICIENT_STORAGE,
    SIZE_OVERFLOW,
    INVALID_STORAGE_SNAPSHOT,
    ENGINE_VERSION_UNSUPPORTED,
    RUNTIME_API_UNSUPPORTED,
    DIGEST_MISMATCH,
}

public data class ModelInstallPlan(
    public val action: ModelInstallAction,
    public val reason: ModelInstallReason?,
    /** Blueprint policy: at least 2x artifact size must be available. */
    public val requiredFreeBytes: Long,
)

public object ModelInstallPlanner {
    public fun plan(
        manifest: ModelArtifactManifest,
        trust: ModelTrust,
        freeBytes: Long,
        existingVerifiedDigest: String?,
        interruptedPartialBytes: Long,
        currentEngineVersion: SemanticVersion = manifest.minimumEngineVersion,
        currentRuntimeApi: SemanticVersion = manifest.runtimeApi,
    ): ModelInstallPlan {
        if (freeBytes < 0L || interruptedPartialBytes < 0L) {
            return rejected(ModelInstallReason.INVALID_STORAGE_SNAPSHOT)
        }
        if (!manifest.isStructurallyValid()) return rejected(ModelInstallReason.INVALID_MANIFEST)
        if (trust != ModelTrust.VERIFIED) return rejected(ModelInstallReason.MANIFEST_UNTRUSTED)
        if (currentEngineVersion < manifest.minimumEngineVersion) {
            return rejected(ModelInstallReason.ENGINE_VERSION_UNSUPPORTED)
        }
        if (currentRuntimeApi < manifest.runtimeApi) {
            return rejected(ModelInstallReason.RUNTIME_API_UNSUPPORTED)
        }
        if (existingVerifiedDigest != null) {
            if (existingVerifiedDigest.equals(manifest.sha256Hex, ignoreCase = true)) {
                return ModelInstallPlan(ModelInstallAction.ALREADY_INSTALLED, null, 0L)
            }
            return rejected(ModelInstallReason.DIGEST_MISMATCH)
        }
        if (manifest.artifactBytes > Long.MAX_VALUE / REQUIRED_FREE_MULTIPLIER) {
            return rejected(ModelInstallReason.SIZE_OVERFLOW)
        }
        val required = manifest.artifactBytes * REQUIRED_FREE_MULTIPLIER
        if (interruptedPartialBytes > 0L) {
            // Partial content is untrusted and must be removed before a fresh attempt.
            return ModelInstallPlan(ModelInstallAction.DELETE_PARTIAL_AND_RESTART, null, required)
        }
        if (freeBytes < required) {
            return ModelInstallPlan(ModelInstallAction.REJECT, ModelInstallReason.INSUFFICIENT_STORAGE, required)
        }
        return ModelInstallPlan(ModelInstallAction.INSTALL, null, required)
    }

    private fun rejected(reason: ModelInstallReason): ModelInstallPlan =
        ModelInstallPlan(ModelInstallAction.REJECT, reason, 0L)

    private fun ModelArtifactManifest.isStructurallyValid(): Boolean =
        schemaVersion == 1 &&
            modelId.isSafeModelId() &&
            artifactBytes > 0L &&
            sha256Hex.length == 64 && sha256Hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' } &&
            licenseId.isNotBlank() &&
            provenance.isNotBlank() &&
            publisherKeyId.isNotBlank() &&
            signatureBase64.isNotBlank()

    private fun String.isSafeModelId(): Boolean =
        length in 3..160 && startsWith("sqrec/") &&
            all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '/' || it == '-' || it == '_' || it == '.' }

    public const val REQUIRED_FREE_MULTIPLIER: Long = 2L
}
