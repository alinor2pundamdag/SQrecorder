package com.alinor.sqrecorder.domain

/**
 * Platform-neutral session lifecycle. Integrity is modeled separately and never
 * inferred from a lifecycle state (for example, STOPPED does not mean intact).
 * Durable incident history belongs to the journal; this in-memory snapshot is bounded.
 */
public data class SessionId(public val value: String)

public enum class SessionPhase {
    PREPARING,
    READY,
    RECORDING,
    STOP_REQUESTED,
    FINALIZING,
    FINALIZED,
    FAILED,
    RECOVERED,
}

public enum class IntegrityStatus {
    CLEAN,
    WARNING,
    INCIDENT,
}

public enum class IntegritySeverity {
    WARNING,
    CRITICAL,
}

public enum class IntegrityCode {
    PCM_QUEUE_PRESSURE,
    INPUT_OVERRUN,
    ROUTE_DISCONTINUITY,
    TIMESTAMP_ESTIMATED,
    STORAGE_FAILURE,
    WAV_FINALIZATION_FAILURE,
    JOURNAL_FAILURE,
    UNKNOWN_CAPTURE_GAP,
    RECOVERED_AFTER_CRASH,
}

public data class IntegrityIncident(
    public val sequence: Long,
    public val monotonicTimestampNs: Long,
    public val code: IntegrityCode,
    public val severity: IntegritySeverity,
)

public enum class StopReason {
    USER_REQUEST,
    STORAGE_LIMIT,
    THERMAL_LIMIT,
    BATTERY_LIMIT,
    CAPTURE_FAILURE,
    PCM_QUEUE_PRESSURE,
    PERMISSION_REVOKED,
    ROUTE_LOSS,
    APP_SHUTDOWN,
}

public enum class SessionFailureCode {
    CAPTURE_START_FAILED,
    CAPTURE_PIPELINE_FAILED,
    STORAGE_UNAVAILABLE,
    FINALIZATION_FAILED,
    JOURNAL_UNAVAILABLE,
    INTERNAL_FAILURE,
}

public data class SessionSnapshot internal constructor(
    public val id: SessionId,
    public val phase: SessionPhase,
    public val integrity: IntegrityStatus,
    public val createdAtNs: Long,
    public val lastEventAtNs: Long,
    public val transitionSequence: Long,
    public val lastIntegritySequence: Long,
    public val integrityIncidentCount: Long,
    public val lastIncident: IntegrityIncident?,
    public val captureEpoch: Long?,
    public val stopReason: StopReason?,
    public val finalizedBytes: Long?,
    public val failureCode: SessionFailureCode?,
) {
    public companion object {
        public fun create(id: SessionId, createdAtNs: Long): SessionSnapshot {
            require(id.value.isNotBlank()) { "SessionId must not be blank" }
            require(createdAtNs >= 0L) { "Monotonic timestamp must be non-negative" }
            return SessionSnapshot(
                id = id,
                phase = SessionPhase.PREPARING,
                integrity = IntegrityStatus.CLEAN,
                createdAtNs = createdAtNs,
                lastEventAtNs = createdAtNs,
                transitionSequence = 0L,
                lastIntegritySequence = 0L,
                integrityIncidentCount = 0L,
                lastIncident = null,
                captureEpoch = null,
                stopReason = null,
                finalizedBytes = null,
                failureCode = null,
            )
        }
    }
}

public sealed interface SessionEvent {
    public val atNs: Long

    public data class PreparationSucceeded(override val atNs: Long) : SessionEvent
    public data class CaptureStarted(
        override val atNs: Long,
        public val captureEpoch: Long,
    ) : SessionEvent
    public data class StopRequested(
        override val atNs: Long,
        public val reason: StopReason,
    ) : SessionEvent
    public data class CaptureStopped(override val atNs: Long) : SessionEvent
    public data class FinalizationSucceeded(
        override val atNs: Long,
        public val finalizedBytes: Long,
    ) : SessionEvent
    public data class FinalizationFailed(
        override val atNs: Long,
        public val code: SessionFailureCode,
    ) : SessionEvent
    public data class Failed(
        override val atNs: Long,
        public val code: SessionFailureCode,
    ) : SessionEvent
    public data class Recovered(
        override val atNs: Long,
        public val recoveredBytes: Long,
    ) : SessionEvent
    public data class IntegrityRaised(
        override val atNs: Long,
        public val incident: IntegrityIncident,
    ) : SessionEvent
}

public enum class TransitionError {
    TIMESTAMP_REGRESSION,
    INVALID_PHASE,
    INVALID_CAPTURE_EPOCH,
    INVALID_FINALIZED_SIZE,
    INVALID_RECOVERY_SIZE,
    INVALID_INCIDENT_SEQUENCE,
    INCIDENT_TIMESTAMP_MISMATCH,
}

public sealed interface TransitionOutcome {
    public val snapshot: SessionSnapshot

    public data class Applied(override val snapshot: SessionSnapshot) : TransitionOutcome
    public data class Rejected(
        override val snapshot: SessionSnapshot,
        public val error: TransitionError,
    ) : TransitionOutcome
}

public object SessionLifecycle {
    public fun reduce(current: SessionSnapshot, event: SessionEvent): TransitionOutcome {
        if (event.atNs < current.lastEventAtNs) {
            return TransitionOutcome.Rejected(current, TransitionError.TIMESTAMP_REGRESSION)
        }

        // Stop is intentionally idempotent: duplicate stop signals do not mutate state.
        if (event is SessionEvent.StopRequested &&
            current.phase in setOf(
                SessionPhase.STOP_REQUESTED,
                SessionPhase.FINALIZING,
                SessionPhase.FINALIZED,
                SessionPhase.FAILED,
                SessionPhase.RECOVERED,
            )
        ) {
            return TransitionOutcome.Applied(current)
        }

        val nextPhase: SessionPhase
        var captureEpoch = current.captureEpoch
        var stopReason = current.stopReason
        var finalizedBytes = current.finalizedBytes
        var failureCode = current.failureCode
        var integrity = current.integrity
        var lastIntegritySequence = current.lastIntegritySequence
        var incidentCount = current.integrityIncidentCount
        var lastIncident = current.lastIncident

        when (event) {
            is SessionEvent.PreparationSucceeded -> {
                if (current.phase != SessionPhase.PREPARING) return invalid(current)
                nextPhase = SessionPhase.READY
            }
            is SessionEvent.CaptureStarted -> {
                if (current.phase != SessionPhase.READY) return invalid(current)
                if (event.captureEpoch <= 0L) {
                    return TransitionOutcome.Rejected(current, TransitionError.INVALID_CAPTURE_EPOCH)
                }
                captureEpoch = event.captureEpoch
                nextPhase = SessionPhase.RECORDING
            }
            is SessionEvent.StopRequested -> {
                if (current.phase != SessionPhase.RECORDING) return invalid(current)
                stopReason = event.reason
                nextPhase = SessionPhase.STOP_REQUESTED
            }
            is SessionEvent.CaptureStopped -> {
                if (current.phase != SessionPhase.STOP_REQUESTED) return invalid(current)
                nextPhase = SessionPhase.FINALIZING
            }
            is SessionEvent.FinalizationSucceeded -> {
                if (current.phase != SessionPhase.FINALIZING) return invalid(current)
                if (event.finalizedBytes < 44L) {
                    return TransitionOutcome.Rejected(current, TransitionError.INVALID_FINALIZED_SIZE)
                }
                finalizedBytes = event.finalizedBytes
                nextPhase = SessionPhase.FINALIZED
            }
            is SessionEvent.FinalizationFailed -> {
                if (current.phase != SessionPhase.FINALIZING) return invalid(current)
                failureCode = event.code
                nextPhase = SessionPhase.FAILED
            }
            is SessionEvent.Failed -> {
                if (current.phase in terminalPhases) return invalid(current)
                failureCode = event.code
                nextPhase = SessionPhase.FAILED
            }
            is SessionEvent.Recovered -> {
                if (current.phase in setOf(SessionPhase.FINALIZED, SessionPhase.RECOVERED)) {
                    return invalid(current)
                }
                if (event.recoveredBytes < 0L) {
                    return TransitionOutcome.Rejected(current, TransitionError.INVALID_RECOVERY_SIZE)
                }
                finalizedBytes = event.recoveredBytes
                nextPhase = SessionPhase.RECOVERED
            }
            is SessionEvent.IntegrityRaised -> {
                if (event.incident.monotonicTimestampNs != event.atNs) {
                    return TransitionOutcome.Rejected(current, TransitionError.INCIDENT_TIMESTAMP_MISMATCH)
                }
                if (event.incident.sequence <= current.lastIntegritySequence ||
                    event.incident.sequence <= 0L ||
                    current.integrityIncidentCount == Long.MAX_VALUE
                ) {
                    return TransitionOutcome.Rejected(current, TransitionError.INVALID_INCIDENT_SEQUENCE)
                }
                lastIntegritySequence = event.incident.sequence
                incidentCount += 1L
                lastIncident = event.incident
                integrity = when (event.incident.severity) {
                    IntegritySeverity.WARNING -> maxIntegrity(integrity, IntegrityStatus.WARNING)
                    IntegritySeverity.CRITICAL -> IntegrityStatus.INCIDENT
                }
                nextPhase = current.phase
            }
        }

        val lifecycleChanged = nextPhase != current.phase
        val updated = current.copy(
            phase = nextPhase,
            integrity = integrity,
            lastEventAtNs = event.atNs,
            transitionSequence = current.transitionSequence + if (lifecycleChanged) 1L else 0L,
            lastIntegritySequence = lastIntegritySequence,
            integrityIncidentCount = incidentCount,
            lastIncident = lastIncident,
            captureEpoch = captureEpoch,
            stopReason = stopReason,
            finalizedBytes = finalizedBytes,
            failureCode = failureCode,
        )
        return TransitionOutcome.Applied(updated)
    }

    private fun invalid(current: SessionSnapshot) =
        TransitionOutcome.Rejected(current, TransitionError.INVALID_PHASE)

    private fun maxIntegrity(current: IntegrityStatus, incoming: IntegrityStatus): IntegrityStatus =
        if (current.ordinal >= incoming.ordinal) current else incoming

    private val terminalPhases = setOf(
        SessionPhase.FINALIZED,
        SessionPhase.FAILED,
        SessionPhase.RECOVERED,
    )
}
