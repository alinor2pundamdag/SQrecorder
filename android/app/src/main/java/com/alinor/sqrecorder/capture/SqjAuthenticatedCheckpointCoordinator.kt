package com.alinor.sqrecorder.capture

import com.alinor.sqrecorder.domain.JournalAnchorSigner
import com.alinor.sqrecorder.domain.VaultAuthContext
import android.os.SystemClock
import com.alinor.sqrecorder.vault.android.AndroidJournalAnchorVerifier
import java.io.File
import java.nio.channels.FileChannel
import java.nio.file.StandardOpenOption

/**
 * Authenticated SQJ checkpoint transaction boundary.
 *
 * Caller invokes this only after the intended journal append returned durable.
 * The signer enforces the short-lived authenticated Vault context. The
 * coordinator re-scans and signs the exact persisted head, persists an
 * immutable SQAC record, then verifies the checkpoint against the retained
 * signing-key resolver before reporting success.
 */
internal class SqjAuthenticatedCheckpointCoordinator(
    private val signer: JournalAnchorSigner,
    private val verifier: AndroidJournalAnchorVerifier,
    private val store: SqjDurableCheckpointStore = SqjDurableCheckpointStore(),
    private val monotonicNowNs: () -> Long = { SystemClock.elapsedRealtimeNanos() },
) {
    fun anchorDurableHead(
        journalFile: File,
        checkpointDirectory: File,
        authContext: VaultAuthContext,
    ): File {
        check(authContext.validate(monotonicNowNs())) {
            "Refusing to checkpoint without a current authenticated Vault context"
        }
        val scan = CaptureSessionJournal.scan(journalFile)
        check(scan.valid && !scan.damagedTail) { "Refusing to sign a damaged or incomplete SQJ" }
        val digest = readTerminalDigest(journalFile)
        val digestHex = digest.joinToString("") { "%02x".format(it) }
        digest.fill(0)

        val anchor = signer.signCommittedDigest(scan.lastSequence, digestHex, authContext)
        check(anchor.sequence == scan.lastSequence && anchor.digestHex == digestHex) {
            "Signer returned an anchor that does not match the durable SQJ head"
        }
        val checkpoint = store.persistAfterJournalSync(journalFile, checkpointDirectory, anchor)
        val verification = store.verifyPersisted(journalFile, checkpoint, verifier)
        check(verification == SqacVerificationResult.VALID) {
            "Persisted SQAC did not verify: $verification; preserve checkpoint and journal"
        }
        return checkpoint
    }

    private fun readTerminalDigest(file: File): ByteArray {
        check(file.length() >= 32L) { "SQJ terminal digest unavailable" }
        return FileChannel.open(file.toPath(), StandardOpenOption.READ).use { channel ->
            val buffer = java.nio.ByteBuffer.allocate(32)
            channel.position(channel.size() - 32L)
            while (buffer.hasRemaining()) {
                val count = channel.read(buffer)
                check(count > 0) { "SQJ terminal digest read made no progress" }
            }
            buffer.array()
        }
    }
}
