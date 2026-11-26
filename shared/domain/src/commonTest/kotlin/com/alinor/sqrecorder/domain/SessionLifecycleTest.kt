package com.alinor.sqrecorder.domain

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class SessionLifecycleTest {
    private fun applied(snapshot: SessionSnapshot, event: SessionEvent): SessionSnapshot =
        assertIs<TransitionOutcome.Applied>(SessionLifecycle.reduce(snapshot, event)).snapshot

    private fun recordingSnapshot(): SessionSnapshot {
        var state = SessionSnapshot.create(SessionId("session-test-01"), 0L)
        state = applied(state, SessionEvent.PreparationSucceeded(1L))
        state = applied(state, SessionEvent.CaptureStarted(2L, captureEpoch = 1L))
        return state
    }

    @Test
    fun preparationAndStartFollowRequiredOrder() {
        val initial = SessionSnapshot.create(SessionId("s1"), 0L)
        val rejected = assertIs<TransitionOutcome.Rejected>(
            SessionLifecycle.reduce(initial, SessionEvent.CaptureStarted(1L, 1L)),
        )
        assertEquals(TransitionError.INVALID_PHASE, rejected.error)
        assertEquals(initial, rejected.snapshot)

        val ready = applied(initial, SessionEvent.PreparationSucceeded(1L))
        val recording = applied(ready, SessionEvent.CaptureStarted(2L, 1L))
        assertEquals(SessionPhase.RECORDING, recording.phase)
        assertEquals(2L, recording.transitionSequence)
    }

    @Test
    fun stopIsIdempotentAndFinalizationIsExplicit() {
        val recording = recordingSnapshot()
        val stopping = applied(
            recording,
            SessionEvent.StopRequested(3L, StopReason.USER_REQUEST),
        )
        val duplicate = applied(stopping, SessionEvent.StopRequested(4L, StopReason.USER_REQUEST))
        assertEquals(stopping, duplicate)

        val finalizing = applied(stopping, SessionEvent.CaptureStopped(5L))
        val finalized = applied(finalizing, SessionEvent.FinalizationSucceeded(6L, 4096L))
        assertEquals(SessionPhase.FINALIZED, finalized.phase)
        assertEquals(4096L, finalized.finalizedBytes)
    }

    @Test
    fun integrityDoesNotChangeLifecycleAndIsMonotonic() {
        val recording = recordingSnapshot()
        val warning = IntegrityIncident(
            sequence = 1L,
            monotonicTimestampNs = 3L,
            code = IntegrityCode.INPUT_OVERRUN,
            severity = IntegritySeverity.WARNING,
        )
        val degraded = applied(recording, SessionEvent.IntegrityRaised(3L, warning))
        assertEquals(SessionPhase.RECORDING, degraded.phase)
        assertEquals(IntegrityStatus.WARNING, degraded.integrity)
        assertEquals(2L, degraded.transitionSequence)
        assertEquals(1L, degraded.integrityIncidentCount)

        val critical = warning.copy(
            sequence = 2L,
            monotonicTimestampNs = 4L,
            severity = IntegritySeverity.CRITICAL,
        )
        val incident = applied(degraded, SessionEvent.IntegrityRaised(4L, critical))
        assertEquals(IntegrityStatus.INCIDENT, incident.integrity)
    }

    @Test
    fun timestampRegressionIsRejectedWithoutMutation() {
        val recording = recordingSnapshot()
        val outcome = assertIs<TransitionOutcome.Rejected>(
            SessionLifecycle.reduce(recording, SessionEvent.StopRequested(1L, StopReason.USER_REQUEST)),
        )
        assertEquals(TransitionError.TIMESTAMP_REGRESSION, outcome.error)
        assertEquals(recording, outcome.snapshot)
    }

    @Test
    fun invalidWavFinalSizeIsRejected() {
        val recording = recordingSnapshot()
        val stopping = applied(recording, SessionEvent.StopRequested(3L, StopReason.USER_REQUEST))
        val finalizing = applied(stopping, SessionEvent.CaptureStopped(4L))
        val outcome = assertIs<TransitionOutcome.Rejected>(
            SessionLifecycle.reduce(finalizing, SessionEvent.FinalizationSucceeded(5L, 43L)),
        )
        assertEquals(TransitionError.INVALID_FINALIZED_SIZE, outcome.error)
        assertEquals(finalizing, outcome.snapshot)
    }

    @Test
    fun failedSessionCanBeRecoveredButFinalizedSessionCannot() {
        val initial = SessionSnapshot.create(SessionId("s2"), 0L)
        val failed = applied(
            initial,
            SessionEvent.Failed(1L, SessionFailureCode.CAPTURE_PIPELINE_FAILED),
        )
        val recovered = applied(failed, SessionEvent.Recovered(2L, 0L))
        assertEquals(SessionPhase.RECOVERED, recovered.phase)

        val rejected = assertIs<TransitionOutcome.Rejected>(
            SessionLifecycle.reduce(
                recovered,
                SessionEvent.Recovered(3L, 10L),
            ),
        )
        assertEquals(TransitionError.INVALID_PHASE, rejected.error)
    }
}
