package com.alinor.sqrecorder.domain

import kotlin.test.Test
import kotlin.test.assertEquals

class ModelInstallPlannerTest {
    private fun manifest(bytes: Long = 100L) = ModelArtifactManifest(
        schemaVersion = 1,
        modelId = "sqrec/model-base",
        version = SemanticVersion(1, 0, 0),
        artifactBytes = bytes,
        sha256Hex = "a".repeat(64),
        licenseId = "Apache-2.0",
        provenance = "signed-catalog",
        runtimeApi = SemanticVersion(1, 0, 0),
        minimumEngineVersion = SemanticVersion(1, 0, 0),
        publisherKeyId = "publisher-key-v1",
        signatureBase64 = "AA==",
    )

    @Test
    fun requiresTwoTimesModelSizeAndRemovesInterruptedPartial() {
        val partial = ModelInstallPlanner.plan(manifest(), ModelTrust.VERIFIED, 50, null, 10)
        assertEquals(ModelInstallAction.DELETE_PARTIAL_AND_RESTART, partial.action)
        assertEquals(200L, partial.requiredFreeBytes)

        val insufficient = ModelInstallPlanner.plan(manifest(), ModelTrust.VERIFIED, 199, null, 0)
        assertEquals(ModelInstallReason.INSUFFICIENT_STORAGE, insufficient.reason)
        assertEquals(ModelInstallAction.REJECT, insufficient.action)
    }

    @Test
    fun rejectsOverflowUntrustedAndNegativeStorage() {
        assertEquals(
            ModelInstallReason.SIZE_OVERFLOW,
            ModelInstallPlanner.plan(manifest(Long.MAX_VALUE), ModelTrust.VERIFIED, 0, null, 0).reason,
        )
        assertEquals(
            ModelInstallReason.MANIFEST_UNTRUSTED,
            ModelInstallPlanner.plan(manifest(), ModelTrust.UNVERIFIED, 500, null, 0).reason,
        )
        assertEquals(
            ModelInstallReason.INVALID_STORAGE_SNAPSHOT,
            ModelInstallPlanner.plan(manifest(), ModelTrust.VERIFIED, -1, null, 0).reason,
        )
    }

    @Test
    fun digestMatchIsIdempotentAndDifferentDigestIsRejected() {
        assertEquals(
            ModelInstallAction.ALREADY_INSTALLED,
            ModelInstallPlanner.plan(manifest(), ModelTrust.VERIFIED, 0, "a".repeat(64), 0).action,
        )
        assertEquals(
            ModelInstallReason.DIGEST_MISMATCH,
            ModelInstallPlanner.plan(manifest(), ModelTrust.VERIFIED, 500, "b".repeat(64), 0).reason,
        )
    }
}
