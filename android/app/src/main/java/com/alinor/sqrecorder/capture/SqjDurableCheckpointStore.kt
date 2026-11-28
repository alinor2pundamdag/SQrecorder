package com.alinor.sqrecorder.capture

import com.alinor.sqrecorder.domain.JournalSignatureAnchor
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardCopyOption
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
            val existing = target.readBytes()
            val identical = existing.contentEquals(encoded)
            existing.fill(0)
            encoded.fill(0)
            check(identical) { "Conflicting checkpoint already exists; preserve both journal and checkpoint" }
            return target
        }

        check(checkpointDirectory.isDirectory || checkpointDirectory.mkdirs()) {
            "Checkpoint directory unavailable"
        }
        val temp = File(checkpointDirectory, ".${target.name}.${java.util.UUID.randomUUID()}.tmp")
        try {
            FileOutputStream(temp, false).use { output ->
                output.write(encoded)
                output.fd.sync()
            }
            // No replacement: an existing checkpoint is evidence, never overwritten.
            Files.move(temp.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE)
            syncDirectory(checkpointDirectory)
        } catch (failure: Exception) {
            // If rename succeeded but directory sync failed, preserve target as
            // ambiguous durable evidence. Only remove an uncommitted temp file.
            if (temp.exists()) temp.delete()
            throw IllegalStateException("SQAC persistence ambiguous; preserve journal and checkpoint evidence", failure)
        } finally {
            encoded.fill(0)
        }
        return target
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
