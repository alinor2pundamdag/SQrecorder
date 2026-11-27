package com.alinor.sqrecorder.domain

public data class ToolId(public val value: String) {
    public fun isValid(): Boolean {
        val parts = value.split('/')
        return parts.size == 2 && parts.all { part ->
            part.isNotEmpty() && part.all {
                it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' || it == '.'
            }
        }
    }
}

public data class SemanticVersion(
    public val major: Int,
    public val minor: Int,
    public val patch: Int,
) : Comparable<SemanticVersion> {
    public fun isValid(): Boolean = major >= 0 && minor >= 0 && patch >= 0

    override fun compareTo(other: SemanticVersion): Int {
        if (major != other.major) return major.compareTo(other.major)
        if (minor != other.minor) return minor.compareTo(other.minor)
        return patch.compareTo(other.patch)
    }

    public fun isApiCompatibleWith(required: SemanticVersion): Boolean =
        isValid() && required.isValid() && major == required.major && this >= required
}

public enum class ToolExecutionClass {
    REALTIME_SAFE,
    DEFERRED,
    BATCH,
}

public enum class ThermalState {
    NOMINAL,
    MODERATE,
    SEVERE,
    CRITICAL,
}

public enum class SelectionPolicy {
    QUALITY_FIRST,
    LOW_LATENCY,
    ENERGY_EFFICIENT,
}

public enum class ManifestTrust {
    VERIFIED,
    UNKNOWN,
    INVALID,
}

public data class ToolProfile(
    public val profileId: String,
    public val modelRef: String?,
    /** Relative ordering only; higher ranks are preferred, not a capability ceiling. */
    public val qualityRank: Int,
    public val estimatedRamBytes: Long,
    public val estimatedStorageBytes: Long,
    public val estimatedLatencyMicros: Long,
    public val estimatedEnergyUnits: Long,
)

public data class ToolManifest(
    public val schemaVersion: Int,
    public val toolId: ToolId,
    public val apiVersion: SemanticVersion,
    public val nativeAbiMajor: Int,
    public val minimumEngineVersion: SemanticVersion,
    public val algorithmRevision: String,
    public val supportedPlatforms: Set<String>,
    public val inputFormats: Set<String>,
    public val outputFormats: Set<String>,
    public val requiredFeatures: Set<String>,
    public val providers: Set<String>,
    public val executionClass: ToolExecutionClass,
    public val profiles: List<ToolProfile>,
    public val digestHex: String,
) {
    public fun validate(): ManifestError? {
        if (schemaVersion != 1) return ManifestError.UNSUPPORTED_SCHEMA
        if (!toolId.isValid() || algorithmRevision.isBlank()) return ManifestError.INVALID_ID
        if (!apiVersion.isValid() || !minimumEngineVersion.isValid()) return ManifestError.INVALID_VERSION
        if (nativeAbiMajor <= 0) return ManifestError.INVALID_ABI
        if (supportedPlatforms.isEmpty() || inputFormats.isEmpty() || outputFormats.isEmpty()) {
            return ManifestError.MISSING_FORMAT_OR_PLATFORM
        }
        if (requiredFeatures.any { it.isBlank() } || providers.any { it.isBlank() }) {
            return ManifestError.INVALID_FEATURE_OR_PROVIDER
        }
        if (profiles.isEmpty() || profiles.any {
                it.profileId.isBlank() ||
                    it.estimatedRamBytes < 0L ||
                    it.estimatedStorageBytes < 0L ||
                    it.estimatedLatencyMicros < 0L ||
                    it.estimatedEnergyUnits < 0L
            }
        ) return ManifestError.INVALID_PROFILE
        if (profiles.map { it.profileId }.distinct().size != profiles.size) {
            return ManifestError.DUPLICATE_PROFILE
        }
        if (!digestHex.isLowerHexDigest()) return ManifestError.INVALID_DIGEST
        return null
    }
}

public enum class ManifestError {
    UNSUPPORTED_SCHEMA,
    INVALID_ID,
    INVALID_VERSION,
    INVALID_ABI,
    MISSING_FORMAT_OR_PLATFORM,
    INVALID_FEATURE_OR_PROVIDER,
    INVALID_PROFILE,
    DUPLICATE_PROFILE,
    INVALID_DIGEST,
}

public data class RuntimeCapabilities(
    public val platformId: String,
    public val engineVersion: SemanticVersion,
    public val nativeAbiMajor: Int,
    public val availableRamBytes: Long,
    public val freeStorageBytes: Long,
    public val supportedFeatures: Set<String>,
    public val availableProviders: Set<String>,
    public val inputFormats: Set<String>,
    public val outputFormats: Set<String>,
    public val installedModelRefs: Set<String>,
    public val thermalState: ThermalState,
    public val captureActive: Boolean,
)

public data class SelectionRequest(
    public val toolId: ToolId,
    public val requiredApiVersion: SemanticVersion,
    public val inputFormat: String,
    public val outputFormat: String,
    public val requiredFeatures: Set<String>,
    public val preferredProvider: String?,
    public val policy: SelectionPolicy,
)

public data class ToolSelection(
    public val toolId: ToolId,
    public val apiVersion: SemanticVersion,
    public val algorithmRevision: String,
    public val manifestDigestHex: String,
    public val profileId: String,
    public val modelRef: String?,
    public val providerId: String,
    public val nativeAbiMajor: Int,
)

public enum class SelectionError {
    MANIFEST_UNTRUSTED,
    MANIFEST_INVALID,
    TOOL_ID_MISMATCH,
    API_INCOMPATIBLE,
    ENGINE_TOO_OLD,
    ABI_MISMATCH,
    PLATFORM_UNSUPPORTED,
    FORMAT_UNSUPPORTED,
    FEATURE_UNAVAILABLE,
    PROVIDER_UNAVAILABLE,
    MODEL_NOT_INSTALLED,
    RESOURCE_UNAVAILABLE,
    PROCESSING_DEFERRED_DURING_CAPTURE,
    THERMAL_DEFERRED,
    NO_ELIGIBLE_PROFILE,
}

public sealed interface SelectionOutcome {
    public data class Selected(public val selection: ToolSelection) : SelectionOutcome
    public data class Rejected(public val error: SelectionError) : SelectionOutcome
}

public object CapabilitySelector {
    public fun select(
        manifest: ToolManifest,
        trust: ManifestTrust,
        runtime: RuntimeCapabilities,
        request: SelectionRequest,
    ): SelectionOutcome {
        if (trust != ManifestTrust.VERIFIED) return SelectionOutcome.Rejected(SelectionError.MANIFEST_UNTRUSTED)
        if (manifest.validate() != null) return SelectionOutcome.Rejected(SelectionError.MANIFEST_INVALID)
        if (manifest.toolId != request.toolId) return SelectionOutcome.Rejected(SelectionError.TOOL_ID_MISMATCH)
        if (!manifest.apiVersion.isApiCompatibleWith(request.requiredApiVersion)) {
            return SelectionOutcome.Rejected(SelectionError.API_INCOMPATIBLE)
        }
        if (runtime.engineVersion < manifest.minimumEngineVersion) {
            return SelectionOutcome.Rejected(SelectionError.ENGINE_TOO_OLD)
        }
        if (manifest.nativeAbiMajor != runtime.nativeAbiMajor) {
            return SelectionOutcome.Rejected(SelectionError.ABI_MISMATCH)
        }
        if (runtime.platformId !in manifest.supportedPlatforms) {
            return SelectionOutcome.Rejected(SelectionError.PLATFORM_UNSUPPORTED)
        }
        if (request.inputFormat !in manifest.inputFormats ||
            request.inputFormat !in runtime.inputFormats ||
            request.outputFormat !in manifest.outputFormats ||
            request.outputFormat !in runtime.outputFormats
        ) return SelectionOutcome.Rejected(SelectionError.FORMAT_UNSUPPORTED)
        if (!(manifest.requiredFeatures + request.requiredFeatures).all {
                it in runtime.supportedFeatures
            }
        ) return SelectionOutcome.Rejected(SelectionError.FEATURE_UNAVAILABLE)

        val providers = manifest.providers intersect runtime.availableProviders
        if (providers.isEmpty()) return SelectionOutcome.Rejected(SelectionError.PROVIDER_UNAVAILABLE)
        val provider = request.preferredProvider?.takeIf { it in providers } ?: providers.sorted().first()

        if (runtime.captureActive && manifest.executionClass != ToolExecutionClass.REALTIME_SAFE) {
            return SelectionOutcome.Rejected(SelectionError.PROCESSING_DEFERRED_DURING_CAPTURE)
        }
        if (runtime.thermalState == ThermalState.CRITICAL &&
            manifest.executionClass != ToolExecutionClass.REALTIME_SAFE
        ) return SelectionOutcome.Rejected(SelectionError.THERMAL_DEFERRED)

        val modelEligible = manifest.profiles.filter { profile ->
            profile.modelRef == null || profile.modelRef in runtime.installedModelRefs
        }
        if (modelEligible.isEmpty()) {
            return SelectionOutcome.Rejected(SelectionError.MODEL_NOT_INSTALLED)
        }
        val eligible = modelEligible.filter { profile ->
            profile.estimatedRamBytes <= runtime.availableRamBytes &&
                profile.estimatedStorageBytes <= runtime.freeStorageBytes
        }
        if (eligible.isEmpty()) {
            return SelectionOutcome.Rejected(SelectionError.RESOURCE_UNAVAILABLE)
        }

        val selected = when (request.policy) {
            SelectionPolicy.QUALITY_FIRST -> eligible.sortedWith(
                compareByDescending<ToolProfile> { it.qualityRank }
                    .thenBy { it.estimatedLatencyMicros }
                    .thenBy { it.estimatedEnergyUnits },
            ).first()
            SelectionPolicy.LOW_LATENCY -> eligible.sortedWith(
                compareBy<ToolProfile> { it.estimatedLatencyMicros }
                    .thenByDescending { it.qualityRank }
                    .thenBy { it.estimatedEnergyUnits },
            ).first()
            SelectionPolicy.ENERGY_EFFICIENT -> eligible.sortedWith(
                compareBy<ToolProfile> { it.estimatedEnergyUnits }
                    .thenByDescending { it.qualityRank }
                    .thenBy { it.estimatedLatencyMicros },
            ).first()
        }

        return SelectionOutcome.Selected(
            ToolSelection(
                toolId = manifest.toolId,
                apiVersion = manifest.apiVersion,
                algorithmRevision = manifest.algorithmRevision,
                manifestDigestHex = manifest.digestHex,
                profileId = selected.profileId,
                modelRef = selected.modelRef,
                providerId = provider,
                nativeAbiMajor = manifest.nativeAbiMajor,
            ),
        )
    }
}

private fun String.isLowerHexDigest(): Boolean =
    length == 64 && all { it in '0'..'9' || it in 'a'..'f' }
