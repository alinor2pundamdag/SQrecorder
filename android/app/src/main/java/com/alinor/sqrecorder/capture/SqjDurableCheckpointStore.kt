package com.alinor.sqrecorder.capture

import com.alinor.sqrecorder.domain.JournalSignatureAnchor
import com.alinor.sqrecorder.vault.android.AndroidJournalAnchorVerifier
import com.alinor.sqrecorder.vault.android.JournalAnchorVerificationResult
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardOpenOption

/**
 * Append-only Android persistence adapter for the portable SQAC v1 signed-anchor
 * checkpoint. Caller must sign only a journal record already forced to storage.
 * This class independently scans/binds the anchor to the exact current journal
 * head before persisting; it never edits, truncates, or repairs the SQJ.
 *
 * Checkpoints are immutable sequence-named files. A crash cannot replace the
 * previous valid checkpoint; a retry for the same sequence is accepted only
 * when its bytes are identical.
 */
internal class SqjDurableCheckpointStore {
    fun persistAfterJournalSync(
        journalFile: File,
        checkpointDirectory: File,
        anchor: JournalSignatureAnchor,
    ): File {
        require(anchor.validate()) { "Invalid SQJ anchor metadata" }
        val scan = CaptureSessionJournal.scan(journalFile)
        check(scan.valid && !scan.damagedTail) { "Cannot checkpoint a damaged SQJ" }
        check(scan.lastSequence == anchor.sequence) { "Anchor sequence is not the exact SQJ head" }
        val terminalDigest = readTerminalDigest(journalFile)
        val digestHex = terminalDigest.joinToString("") { "%02x".format(it) }
        terminalDigest.fill(0)
        check(digestHex == anchor.digestHex) { "Anchor digest is not the exact SQJ head" }

        val encoded = encodeCanonicalSqac(anchor)
        val target = File(checkpointDirectory, "sqac-${anchor.sequence.toString().padStart(20, '0')}.checkpoint")
        if (target.exists()) {
            val existing = try {
                readCheckpointBounded(target)
            } catch (failure: Exception) {
                encoded.fill(0)
                throw IllegalStateException("Existing checkpoint is malformed; preserve it", failure)
            }
            check(existing.size == encoded.size) {
                existing.fill(0)
                encoded.fill(0)
                error("Existing checkpoint length conflicts with canonical encoding; preserve it")
            }
            val identical = existing.contentEquals(encoded)
            existing.fill(0)
            encoded.fill(0)
            check(identical) { "Conflicting checkpoint already exists; preserve both journal and checkpoint" }
            return target
        }

        val checkpointParent = checkpointDirectory.absoluteFile.parentFile
        check(checkpointParent?.isDirectory == true) {
            "Checkpoint parent must exist before durable checkpoint creation"
        }
        val createdDirectory = !checkpointDirectory.exists()
        check(checkpointDirectory.isDirectory || checkpointDirectory.mkdir()) {
            "Checkpoint directory unavailable"
        }
        if (createdDirectory) syncDirectory(checkpointParent)
        val temp = File(checkpointDirectory, ".${target.name}.${java.util.UUID.randomUUID()}.tmp")
        var tempCreated = false
        try {
            FileChannel.open(
                temp.toPath(),
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE,
            ).use { channel ->
                tempCreated = true
                var buffer = ByteBuffer.wrap(encoded)
                while (buffer.hasRemaining()) {
                    val written = channel.write(buffer)
                    check(written > 0) { "Checkpoint write made no progress" }
                }
                channel.force(true)
            }
            // Hard-link publication is atomic and no-clobber on the same
            // filesystem. Never rely on ATOMIC_MOVE's provider-specific
            // behavior when a target name already exists.
            android.system.Os.link(temp.absolutePath, target.absolutePath)
            syncDirectory(checkpointDirectory)
            Files.delete(temp.toPath())
            syncDirectory(checkpointDirectory)
        } catch (failure: Exception) {
            // If rename succeeded but directory sync failed, preserve target as
            // ambiguous durable evidence. Only remove an uncommitted temp file.
            if (tempCreated && temp.exists()) temp.delete()
            throw IllegalStateException("SQAC persistence ambiguous; preserve journal and checkpoint evidence", failure)
        } finally {
            encoded.fill(0)
        }
        return target
    }


    /** Reads a persisted SQAC file and verifies both signature and exact journal-head binding. */
    fun verifyPersisted(
        journalFile: File,
        checkpointFile: File,
        verifier: AndroidJournalAnchorVerifier,
    ): SqacVerificationResult {
        val bytes = try {
            readCheckpointBounded(checkpointFile)
        } catch (_: Exception) {
            return SqacVerificationResult.INVALID_CHECKPOINT
        }
        val anchor = try {
            decodeCanonicalSqac(bytes)
        } catch (_: Exception) {
            bytes.fill(0)
            return SqacVerificationResult.INVALID_CHECKPOINT
        }
        bytes.fill(0)
        val scan = CaptureSessionJournal.scan(journalFile)
        if (!scan.valid || scan.damagedTail) return SqacVerificationResult.JOURNAL_DAMAGED
        if (scan.lastSequence != anchor.sequence) return SqacVerificationResult.SEQUENCE_MISMATCH
        val terminalDigest = try {
            readTerminalDigest(journalFile)
        } catch (_: Exception) {
            return SqacVerificationResult.JOURNAL_DAMAGED
        }
        val digestHex = terminalDigest.joinToString("") { "%02x".format(it) }
        terminalDigest.fill(0)
        if (digestHex != anchor.digestHex) return SqacVerificationResult.DIGEST_MISMATCH
        return when (verifier.verify(anchor)) {
            JournalAnchorVerificationResult.VALID -> SqacVerificationResult.VALID
            JournalAnchorVerificationResult.KEY_NOT_FOUND -> SqacVerificationResult.RETAINED_KEY_MISSING
            else -> SqacVerificationResult.INVALID_SIGNATURE
        }
    }

    private fun decodeCanonicalSqac(bytes: ByteArray): JournalSignatureAnchor {
        require(bytes.size in 71..340)
        require(bytes.copyOfRange(0, 4).contentEquals(byteArrayOf(0x53, 0x51, 0x41, 0x43)))
        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        require(buffer.getShort(4).toInt() == 1)
        val sequence = buffer.getLong(6)
        val digest = bytes.copyOfRange(14, 46).joinToString("") { "%02x".format(it) }
        val epoch = buffer.getLong(46)
        val timestamp = buffer.getLong(54)
        val algorithmLength = buffer.getShort(62).toInt() and 0xffff
        val keyLength = buffer.getShort(64).toInt() and 0xffff
        val signatureLength = buffer.getShort(66).toInt() and 0xffff
        require(algorithmLength in 1..64 && keyLength in 1..128 && signatureLength in 1..80)
        require(bytes.size == 68 + algorithmLength + keyLength + signatureLength)
        val algorithmStart = 68
        val keyStart = algorithmStart + algorithmLength
        val signatureStart = keyStart + keyLength
        val algorithm = strictUtf8(bytes.copyOfRange(algorithmStart, keyStart))
        val keyId = strictUtf8(bytes.copyOfRange(keyStart, signatureStart))
        val signature = bytes.copyOfRange(signatureStart, bytes.size)
        val anchor = JournalSignatureAnchor(
            formatVersion = 1,
            sequence = sequence,
            digestHex = digest,
            signatureAlgorithmId = algorithm,
            signingKeyId = keyId,
            signatureBase64 = encodeStandardBase64(signature),
            authenticationEpoch = epoch,
            monotonicTimestampNs = timestamp,
        )
        signature.fill(0)
        require(anchor.validate())
        return anchor
    }

    private fun strictUtf8(bytes: ByteArray): String =
        Charsets.UTF_8.newDecoder()
            .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
            .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes)).toString().also { bytes.fill(0) }

    private fun encodeStandardBase64(bytes: ByteArray): String {
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        val output = StringBuilder(((bytes.size + 2) / 3) * 4)
        var i = 0
        while (i < bytes.size) {
            val a = bytes[i].toInt() and 0xff
            val hasB = i + 1 < bytes.size
            val hasC = i + 2 < bytes.size
            val b = if (hasB) bytes[i + 1].toInt() and 0xff else 0
            val d = if (hasC) bytes[i + 2].toInt() and 0xff else 0
            val block = (a shl 16) or (b shl 8) or d
            output.append(alphabet[(block ushr 18) and 63])
            output.append(alphabet[(block ushr 12) and 63])
            output.append(if (hasB) alphabet[(block ushr 6) and 63] else '=')
            output.append(if (hasC) alphabet[block and 63] else '=')
            i += 3
        }
        return output.toString()
    }


    private fun readCheckpointBounded(file: File): ByteArray =
        FileChannel.open(file.toPath(), StandardOpenOption.READ).use { channel ->
            val size = channel.size()
            check(size in 71L..340L) { "SQAC size outside canonical bounds" }
            val buffer = ByteBuffer.allocate(size.toInt())
            while (buffer.hasRemaining()) {
                val count = channel.read(buffer)
                check(count > 0) { "SQAC read made no progress" }
            }
            check(channel.size() == size) { "SQAC changed during bounded read" }
            buffer.array()
        }

    private fun readTerminalDigest(file: File): ByteArray {
        val length = file.length()
        check(length >= 32L) { "SQJ terminal digest missing" }
        return FileChannel.open(file.toPath(), StandardOpenOption.READ).use { channel ->
            val buffer = ByteBuffer.allocate(32)
            channel.position(length - 32L)
            while (buffer.hasRemaining()) {
                val count = channel.read(buffer)
                check(count > 0) { "Unable to read SQJ terminal digest" }
            }
            buffer.array()
        }
    }

    private fun syncDirectory(directory: File) {
        FileChannel.open(directory.toPath(), StandardOpenOption.READ).use { it.force(true) }
    }

    private fun encodeCanonicalSqac(anchor: JournalSignatureAnchor): ByteArray {
        val algorithm = anchor.signatureAlgorithmId.toByteArray(Charsets.UTF_8)
        val keyId = anchor.signingKeyId.toByteArray(Charsets.UTF_8)
        val signature = decodeStandardBase64(anchor.signatureBase64)
            ?: error("Anchor signature is not canonical standard Base64")
        require(algorithm.size in 1..64 && keyId.size in 1..128 && signature.size in 1..80)
        val total = 68 + algorithm.size + keyId.size + signature.size
        return ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN).apply {
            put(byteArrayOf(0x53, 0x51, 0x41, 0x43)) // SQAC
            putShort(1)
            putLong(anchor.sequence)
            put(anchor.digestHex.hexToBytes())
            putLong(anchor.authenticationEpoch)
            putLong(anchor.monotonicTimestampNs)
            putShort(algorithm.size.toShort())
            putShort(keyId.size.toShort())
            putShort(signature.size.toShort())
            put(algorithm)
            put(keyId)
            put(signature)
        }.array().also {
            algorithm.fill(0)
            keyId.fill(0)
            signature.fill(0)
        }
    }

    private fun decodeStandardBase64(value: String): ByteArray? {
        if (value.isEmpty() || value.length % 4 != 0) return null
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        val padding = value.takeLastWhile { it == '=' }.length
        if (padding > 2 || value.dropLast(padding).any { it == '=' }) return null
        val output = ByteArray(value.length / 4 * 3 - padding)
        var out = 0
        var i = 0
        while (i < value.length) {
            val a = alphabet.indexOf(value[i])
            val b = alphabet.indexOf(value[i + 1])
            val c = if (value[i + 2] == '=') 0 else alphabet.indexOf(value[i + 2])
            val d = if (value[i + 3] == '=') 0 else alphabet.indexOf(value[i + 3])
            if (a < 0 || b < 0 || c < 0 || d < 0) {
                output.fill(0)
                return null
            }
            val block = (a shl 18) or (b shl 12) or (c shl 6) or d
            if (out < output.size) output[out++] = (block ushr 16).toByte()
            if (out < output.size) output[out++] = (block ushr 8).toByte()
            if (out < output.size) output[out++] = block.toByte()
            i += 4
        }
        if (padding == 1 && (alphabet.indexOf(value[value.length - 2]) and 0x03) != 0 ||
            padding == 2 && (alphabet.indexOf(value[value.length - 3]) and 0x0f) != 0) {
            output.fill(0)
            return null
        }
        return output
    }

    private fun String.hexToBytes(): ByteArray {
        require(length == 64 && all { it in '0'..'9' || it in 'a'..'f' })
        return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
}


internal enum class SqacVerificationResult {
    VALID,
    INVALID_CHECKPOINT,
    JOURNAL_DAMAGED,
    SEQUENCE_MISMATCH,
    DIGEST_MISMATCH,
    RETAINED_KEY_MISSING,
    INVALID_SIGNATURE,
}

