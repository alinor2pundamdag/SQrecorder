package com.alinor.sqrecorder.capture

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel
import java.nio.file.StandardOpenOption
import java.security.MessageDigest
import java.util.UUID

/**
 * Android durable SQJ v1 append adapter matching core/session-journal's exact
 * record framing and digest chain. This writes metadata only; never PCM, keys,
 * or plaintext audio. A partial append/sync error permanently latches this
 * writer so recovery must scan the original bytes rather than retry in place.
 */
internal class CaptureSessionJournal private constructor(
    private val channel: FileChannel,
    private val sessionUuid: ByteArray,
) : AutoCloseable {
    private var sequence = 1L
    private var previousDigest = ByteArray(DIGEST_BYTES)
    private var lastTimestampNs: Long? = null
    private var terminal = false

    @Synchronized
    fun append(recordType: Int, timestampNs: Long, fields: Map<String, Long> = emptyMap()): ByteArray {
        check(!terminal) { "SQJ writer is terminal; preserve journal for recovery" }
        require(recordType in RECORD_SESSION_CREATED..RECORD_MIGRATION_APPENDED)
        require(timestampNs >= 0L && (lastTimestampNs == null || timestampNs >= lastTimestampNs!!))
        require(fields.keys.none { it == "eventCode" || it == "schemaVersion" })
        val payloadFields = fields.toMutableMap().apply {
            put("eventCode", recordType.toLong())
            put("schemaVersion", JOURNAL_VERSION.toLong())
        }
        val payload = canonicalNumericJson(payloadFields)
        require(payload.size <= MAX_PAYLOAD_BYTES)

        val bodyLength = Math.addExact(MIN_BODY_BYTES, payload.size)
        val record = ByteBuffer.allocate(Math.addExact(4, bodyLength)).order(ByteOrder.LITTLE_ENDIAN)
        record.putInt(bodyLength)
        record.put(MAGIC)
        record.putShort(JOURNAL_VERSION.toShort())
        record.putShort(recordType.toShort())
        record.putLong(sequence)
        record.putLong(timestampNs)
        record.put(sessionUuid)
        record.put(previousDigest)
        record.putInt(payload.size)
        record.put(payload)

        val bodyWithoutDigest = record.array().copyOfRange(4, record.position())
        val digest = MessageDigest.getInstance("SHA-256").run {
            update(DIGEST_DOMAIN)
            update(previousDigest)
            update(bodyWithoutDigest)
            digest()
        }
        record.put(digest)
        val bytes = record.array()
        try {
            channel.position(channel.size())
            var buffer = ByteBuffer.wrap(bytes)
            while (buffer.hasRemaining()) channel.write(buffer)
            channel.force(true)
        } catch (failure: Exception) {
            terminal = true
            bodyWithoutDigest.fill(0)
            payload.fill(0)
            bytes.fill(0)
            digest.fill(0)
            throw IllegalStateException("SQJ append/sync ambiguous; preserve and recover journal", failure)
        }
        previousDigest.fill(0)
        previousDigest = digest.copyOf()
        lastTimestampNs = timestampNs
        sequence = Math.addExact(sequence, 1L)
        bodyWithoutDigest.fill(0)
        payload.fill(0)
        return digest
    }

    override fun close() {
        synchronized(this) {
            previousDigest.fill(0)
            sessionUuid.fill(0)
            channel.close()
        }
    }

    companion object {
        const val RECORD_SESSION_CREATED = 1
        const val RECORD_CAPTURE_STARTED = 2
        const val RECORD_CAPTURE_STOP_REQUESTED = 3
        const val RECORD_CAPTURE_STOPPED = 4
        const val RECORD_INTEGRITY_INCIDENT = 5
        const val RECORD_FILE_FINALIZED = 6
        const val RECORD_VAULT_ENCRYPTION_STARTED = 7
        const val RECORD_VAULT_ENCRYPTION_COMPLETED = 8
        const val RECORD_RECOVERY_COMPLETED = 9
        const val RECORD_MIGRATION_APPENDED = 10
        private const val JOURNAL_VERSION = 1
        private const val MIN_BODY_BYTES = 108
        private const val DIGEST_BYTES = 32
        private const val MAX_PAYLOAD_BYTES = 64 * 1024
        private val MAGIC = byteArrayOf(0x53, 0x51, 0x4a, 0x52)
        private val DIGEST_DOMAIN = byteArrayOf(0x53, 0x51, 0x4a, 0x31)

        fun create(file: File, sessionId: UUID): CaptureSessionJournal {
            val parent = file.parentFile ?: error("SQJ parent directory missing")
            check(parent.isDirectory || parent.mkdirs()) { "SQJ parent directory unavailable" }
            val channel = FileChannel.open(
                file.toPath(),
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE,
            )
            try {
                FileChannel.open(parent.toPath(), StandardOpenOption.READ).use { it.force(true) }
            } catch (failure: Exception) {
                channel.close()
                throw IllegalStateException("SQJ directory entry could not be synced", failure)
            }
            val uuidBytes = ByteBuffer.allocate(16).order(ByteOrder.BIG_ENDIAN).apply {
                putLong(sessionId.mostSignificantBits)
                putLong(sessionId.leastSignificantBits)
            }.array()
            return CaptureSessionJournal(channel, uuidBytes)
        }

        private fun canonicalNumericJson(fields: Map<String, Long>): ByteArray {
            // All emitted keys are ASCII and numeric; lexical sorting matches
            // RFC 8785/JCS for this restricted event payload schema.
            val text = fields.toSortedMap().entries.joinToString(
                prefix = "{",
                postfix = "}",
                separator = ",",
            ) { (key, value) -> "\"$key\":$value" }
            return text.toByteArray(Charsets.UTF_8)
        }
    }
}
