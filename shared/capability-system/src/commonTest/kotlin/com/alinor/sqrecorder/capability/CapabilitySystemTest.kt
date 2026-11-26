package com.alinor.sqrecorder.domain

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class CapabilitySystemTest {
    private fun manifest(execution: ToolExecutionClass = ToolExecutionClass.BATCH) = ToolManifest(
        schemaVersion = 1,
        toolId = ToolId("sqrec/transcribe"),
        apiVersion = SemanticVersion(1, 2, 0),
        nativeAbiMajor = 1,
        minimumEngineVersion = SemanticVersion(1, 0, 0),
        algorithmRevision = "whisper-local-r3",
        supportedPlatforms = setOf("android"),
        inputFormats = setOf("wav/pcm-s16le-mono"),
        outputFormats = setOf("text/utf8"),
        requiredFeatures = setOf("offline-inference"),
        providers = setOf("cpu", "nnapi"),
        executionClass = execution,
        profiles = listOf(
            ToolProfile("balanced", "model/base@1", 70, 512, 0, 120_000, 40),
            ToolProfile("quality", "model/large@2", 95, 1536, 0, 220_000, 90),
        ),
        digestHex = "a".repeat(64),
    )

    private fun runtime(captureActive: Boolean = false) = RuntimeCapabilities(
        platformId = "android",
        engineVersion = SemanticVersion(1, 4, 0),
        nativeAbiMajor = 1,
        availableRamBytes = 2_000,
        freeStorageBytes = 1_000,
        supportedFeatures = setOf("offline-inference"),
        availableProviders = setOf("cpu", "nnapi"),
        inputFormats = setOf("wav/pcm-s16le-mono"),
        outputFormats = setOf("text/utf8"),
        installedModelRefs = setOf("model/base@1", "model/large@2"),
        thermalState = ThermalState.NOMINAL,
        captureActive = captureActive,
    )

    private fun request(policy: SelectionPolicy = SelectionPolicy.QUALITY_FIRST) = SelectionRequest(
        toolId = ToolId("sqrec/transcribe"),
        requiredApiVersion = SemanticVersion(1, 0, 0),
        inputFormat = "wav/pcm-s16le-mono",
        outputFormat = "text/utf8",
        requiredFeatures = emptySet(),
        preferredProvider = "nnapi",
        policy = policy,
    )

    @Test
    fun verifiedManifestSelectsBestEligibleProfileAndProvider() {
        val result = CapabilitySelector.select(manifest(), ManifestTrust.VERIFIED, runtime(), request())
        val selected = assertIs<SelectionOutcome.Selected>(result).selection
        assertEquals("quality", selected.profileId)
        assertEquals("nnapi", selected.providerId)
        assertEquals("whisper-local-r3", selected.algorithmRevision)
    }

    @Test
    fun selectorRejectsUntrustedManifestAndAbiMismatch() {
        assertEquals(
            SelectionError.MANIFEST_UNTRUSTED,
            assertIs<SelectionOutcome.Rejected>(
                CapabilitySelector.select(manifest(), ManifestTrust.UNKNOWN, runtime(), request()),
            ).error,
        )
        assertEquals(
            SelectionError.ABI_MISMATCH,
            assertIs<SelectionOutcome.Rejected>(
                CapabilitySelector.select(
                    manifest(),
                    ManifestTrust.VERIFIED,
                    runtime().copy(nativeAbiMajor = 2),
                    request(),
                ),
            ).error,
        )
    }

    @Test
    fun heavyWorkIsDeferredDuringCapture() {
        val result = CapabilitySelector.select(
            manifest(ToolExecutionClass.DEFERRED),
            ManifestTrust.VERIFIED,
            runtime(captureActive = true),
            request(),
        )
        assertEquals(
            SelectionError.PROCESSING_DEFERRED_DURING_CAPTURE,
            assertIs<SelectionOutcome.Rejected>(result).error,
        )
    }

    @Test
    fun modelInstallRequiresTwoTimesSizeAndDeletesInterruptedPartial() {
        val model = ModelArtifactManifest(
            schemaVersion = 1,
            modelId = "sqrec/asr-base",
            version = SemanticVersion(1, 0, 0),
            artifactBytes = 100L,
            sha256Hex = "b".repeat(64),
            licenseId = "Apache-2.0",
            provenance = "publisher-catalog-entry",
            runtimeApi = SemanticVersion(1, 0, 0),
            minimumEngineVersion = SemanticVersion(1, 0, 0),
            publisherKeyId = "publisher-key-1",
            signatureBase64 = "AA==",
        )
        val plan = ModelInstallPlanner.plan(
            model,
            ModelTrust.VERIFIED,
            freeBytes = 50L,
            existingVerifiedDigest = null,
            interruptedPartialBytes = 10L,
        )
        assertEquals(ModelInstallAction.DELETE_PARTIAL_AND_RESTART, plan.action)
        assertEquals(200L, plan.requiredFreeBytes)

        val insufficient = ModelInstallPlanner.plan(
            model,
            ModelTrust.VERIFIED,
            freeBytes = 199L,
            existingVerifiedDigest = null,
            interruptedPartialBytes = 0L,
        )
        assertEquals(ModelInstallReason.INSUFFICIENT_STORAGE, insufficient.reason)
    }

    @Test
    fun modelSizeOverflowFailsClosed() {
        val model = ModelArtifactManifest(
            schemaVersion = 1,
            modelId = "sqrec/model-overflow",
            version = SemanticVersion(1, 0, 0),
            artifactBytes = Long.MAX_VALUE,
            sha256Hex = "c".repeat(64),
            licenseId = "test",
            provenance = "test-fixture",
            runtimeApi = SemanticVersion(1, 0, 0),
            minimumEngineVersion = SemanticVersion(1, 0, 0),
            publisherKeyId = "publisher-key",
            signatureBase64 = "AA==",
        )
        assertEquals(
            ModelInstallReason.SIZE_OVERFLOW,
            ModelInstallPlanner.plan(model, ModelTrust.VERIFIED, 0L, null, 0L).reason,
        )
    }
    @Test
    fun negativeStorageSnapshotIsRejected() {
        val model = ModelArtifactManifest(
            schemaVersion = 1,
            modelId = "sqrec/model-storage-check",
            version = SemanticVersion(1, 0, 0),
            artifactBytes = 10L,
            sha256Hex = "d".repeat(64),
            licenseId = "test",
            provenance = "test-fixture",
            runtimeApi = SemanticVersion(1, 0, 0),
            minimumEngineVersion = SemanticVersion(1, 0, 0),
            publisherKeyId = "publisher-key",
            signatureBase64 = "AA==",
        )
        assertEquals(
            ModelInstallReason.INVALID_STORAGE_SNAPSHOT,
            ModelInstallPlanner.plan(model, ModelTrust.VERIFIED, -1L, null, 0L).reason,
        )
    }

}
