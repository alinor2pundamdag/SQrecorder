package com.alinor.sqrecorder.domain

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
) {
    public fun validate(): ModelManifestError? {
        if (schemaVersion != 1) return ModelManifestError.UNSUPPORTED_SCHEMA
        if (modelId.isBlank() || !version.isValid() || !runtimeApi.isValid() ||
            !minimumEngineVersion.isValid()
        ) return ModelManifestError.INVALID_ID_OR_VERSION
        if (artifactBytes <= 0L) return ModelManifestError.INVALID_SIZE
        if (!sha256Hex.isLowerHexDigest()) return ModelManifestError.INVALID_DIGEST
        if (licenseId.isBlank() || provenance.isBlank() || publisherKeyId.isBlank() ||
            !signatureBase64.isStandardBase64()
        ) return ModelManifestError.MISSING_PROVENANCE_OR_SIGNATURE
        return null
    }
}

public enum class ModelManifestError {
    UNSUPPORTED_SCHEMA,
    INVALID_ID_OR_VERSION,
    INVALID_SIZE,
    INVALID_DIGEST,
    MISSING_PROVENANCE_OR_SIGNATURE,
}

public enum class ModelTrust {
    VERIFIED,
    UNKNOWN_PUBLISHER,
    INVALID_SIGNATURE,
    DIGEST_MISMATCH,
}

public enum class ModelInstallAction {
    INSTALL_TO_STAGING,
    DELETE_PARTIAL_AND_RESTART,
    REUSE_VERIFIED,
    REJECT,
}

public enum class ModelInstallReason {
    READY,
    ALREADY_INSTALLED,
    INSUFFICIENT_STORAGE,
    SIZE_OVERFLOW,
    MANIFEST_INVALID,
    MODEL_UNTRUSTED,
    PARTIAL_RESTART_REQUIRED,
    INVALID_STORAGE_SNAPSHOT,
}

public data class ModelInstallPlan(
    public val action: ModelInstallAction,
    public val reason: ModelInstallReason,
    public val requiredFreeBytes: Long?,
)

public object ModelInstallPlanner {
    /** Requires 2x artifact size free to stage, verify, and atomically promote. */
    public fun plan(
        manifest: ModelArtifactManifest,
        trust: ModelTrust,
        freeBytes: Long,
        existingVerifiedDigest: String?,
        interruptedPartialBytes: Long,
    ): ModelInstallPlan {
        if (manifest.validate() != null) {
            return ModelInstallPlan(ModelInstallAction.REJECT, ModelInstallReason.MANIFEST_INVALID, null)
        }
        if (trust != ModelTrust.VERIFIED) {
            return ModelInstallPlan(ModelInstallAction.REJECT, ModelInstallReason.MODEL_UNTRUSTED, null)
        }
        if (freeBytes < 0L || interruptedPartialBytes < 0L) {
            return ModelInstallPlan(
                ModelInstallAction.REJECT,
                ModelInstallReason.INVALID_STORAGE_SNAPSHOT,
                null,
            )
        }
        if (existingVerifiedDigest == manifest.sha256Hex) {
            return ModelInstallPlan(ModelInstallAction.REUSE_VERIFIED, ModelInstallReason.ALREADY_INSTALLED, 0L)
        }
        val required = manifest.artifactBytes.checkedTimesTwo()
            ?: return ModelInstallPlan(ModelInstallAction.REJECT, ModelInstallReason.SIZE_OVERFLOW, null)

        // Interrupted partials are explicitly discarded before a fresh capacity check.
        if (interruptedPartialBytes > 0L) {
            return ModelInstallPlan(
                ModelInstallAction.DELETE_PARTIAL_AND_RESTART,
                ModelInstallReason.PARTIAL_RESTART_REQUIRED,
                required,
            )
        }
        if (freeBytes < required) {
            return ModelInstallPlan(ModelInstallAction.REJECT, ModelInstallReason.INSUFFICIENT_STORAGE, required)
        }
        return ModelInstallPlan(ModelInstallAction.INSTALL_TO_STAGING, ModelInstallReason.READY, required)
    }
}

private fun Long.checkedTimesTwo(): Long? =
    if (this > Long.MAX_VALUE / 2L) null else this * 2L

private fun String.isLowerHexDigest(): Boolean =
    length == 64 && all { it in '0'..'9' || it in 'a'..'f' }

private fun String.isStandardBase64(): Boolean {
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
    return true
}
