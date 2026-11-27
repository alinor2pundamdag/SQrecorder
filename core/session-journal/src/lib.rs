//! Append-only, hash-chained SQJ v1 journal writer and recovery scanner.
#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};

pub const JOURNAL_MAGIC: &[u8; 4] = b"SQJR";
pub const JOURNAL_DIGEST_DOMAIN: &[u8; 4] = b"SQJ1";
pub const JOURNAL_VERSION: u16 = 1;
pub const JOURNAL_DIGEST_BYTES: usize = 32;
pub const JOURNAL_MIN_BODY_BYTES: usize = 108;
/// SQJ stores metadata only; bounding payloads limits parser and recovery memory use.
pub const JOURNAL_MAX_PAYLOAD_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum JournalRecordType {
    SessionCreated = 1,
    CaptureStarted = 2,
    CaptureStopRequested = 3,
    CaptureStopped = 4,
    IntegrityIncident = 5,
    FileFinalized = 6,
    VaultEncryptionStarted = 7,
    VaultEncryptionCompleted = 8,
    RecoveryCompleted = 9,
    MigrationAppended = 10,
}

impl JournalRecordType {
    fn from_code(code: u16) -> Option<Self> {
        Some(match code {
            1 => Self::SessionCreated,
            2 => Self::CaptureStarted,
            3 => Self::CaptureStopRequested,
            4 => Self::CaptureStopped,
            5 => Self::IntegrityIncident,
            6 => Self::FileFinalized,
            7 => Self::VaultEncryptionStarted,
            8 => Self::VaultEncryptionCompleted,
            9 => Self::RecoveryCompleted,
            10 => Self::MigrationAppended,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalError {
    InvalidRecord,
    InvalidPayloadJson,
    DuplicateJsonKey,
    PayloadTooLarge,
    PayloadSchemaMismatch,
    SequenceMismatch,
    TimestampRegression,
    PreviousDigestMismatch,
    LengthOverflow,
    AllocationFailed,
    SinkAppendFailed,
    SinkSyncFailed,
    WriterTerminal,
    SequenceExhausted,
}

pub struct JournalRecordInput<'a> {
    pub sequence: u64,
    pub monotonic_timestamp_ns: u64,
    pub session_uuid: [u8; 16],
    pub record_type: JournalRecordType,
    /// Canonical UTF-8 JSON metadata (RFC 8785/JCS); never audio, plaintext, or key material.
    pub canonical_payload: &'a [u8],
    pub previous_digest: [u8; JOURNAL_DIGEST_BYTES],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalAppendReceipt {
    pub sequence: u64,
    pub digest: [u8; JOURNAL_DIGEST_BYTES],
    pub serialized_bytes: u32,
}

/// Platform sink must append all bytes and fsync/sync before returning success.
/// It exposes no truncate/overwrite operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalSinkError {
    WriteFailed,
    SyncFailed,
}

pub trait JournalSink {
    fn append_bytes(&mut self, record_bytes: &[u8]) -> Result<(), JournalSinkError>;
    fn sync(&mut self) -> Result<(), JournalSinkError>;
}

pub struct JournalWriter<S: JournalSink> {
    sink: S,
    next_sequence: Option<u64>,
    previous_digest: [u8; JOURNAL_DIGEST_BYTES],
    last_monotonic_timestamp_ns: Option<u64>,
    terminal: bool,
}

impl<S: JournalSink> JournalWriter<S> {
    pub fn new(sink: S) -> Self {
        Self {
            sink,
            next_sequence: Some(1),
            previous_digest: [0u8; JOURNAL_DIGEST_BYTES],
            last_monotonic_timestamp_ns: None,
            terminal: false,
        }
    }

    pub fn append(
        &mut self,
        input: JournalRecordInput<'_>,
    ) -> Result<JournalAppendReceipt, JournalError> {
        if self.terminal {
            return Err(JournalError::WriterTerminal);
        }
        let expected_sequence = self.next_sequence.ok_or(JournalError::SequenceExhausted)?;
        if input.sequence != expected_sequence {
            return Err(JournalError::SequenceMismatch);
        }
        if input.previous_digest != self.previous_digest {
            return Err(JournalError::PreviousDigestMismatch);
        }
        if self
            .last_monotonic_timestamp_ns
            .is_some_and(|last| input.monotonic_timestamp_ns < last)
        {
            return Err(JournalError::TimestampRegression);
        }

        let (serialized, digest) = serialize_record(&input)?;
        let serialized_bytes =
            u32::try_from(serialized.len()).map_err(|_| JournalError::LengthOverflow)?;
        if self.sink.append_bytes(&serialized).is_err() {
            self.terminal = true; // A partial append must be recovered; never retry in-place.
            return Err(JournalError::SinkAppendFailed);
        }
        if self.sink.sync().is_err() {
            self.terminal = true; // Record durability is ambiguous until restart/recovery.
            return Err(JournalError::SinkSyncFailed);
        }

        self.previous_digest = digest;
        self.last_monotonic_timestamp_ns = Some(input.monotonic_timestamp_ns);
        self.next_sequence = input.sequence.checked_add(1);
        Ok(JournalAppendReceipt {
            sequence: input.sequence,
            digest,
            serialized_bytes,
        })
    }

    pub fn into_sink(self) -> S {
        self.sink
    }
}


/// Reject duplicate JSON object keys before serde_json::Value collapses them.
/// Escaped spellings are decoded before comparison (e.g. "x" and "\u0078").
fn has_duplicate_json_keys(bytes: &[u8]) -> bool {
    struct Scanner<'a> { bytes: &'a [u8], pos: usize }
    impl Scanner<'_> {
        fn ws(&mut self) {
            while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_whitespace() { self.pos += 1; }
        }
        fn string_end(&self, start: usize) -> Option<usize> {
            if self.bytes.get(start) != Some(&b'"') { return None; }
            let mut i = start + 1;
            while i < self.bytes.len() {
                match self.bytes[i] {
                    b'"' => return Some(i + 1),
                    b'\\' => i = i.checked_add(2)?,
                    byte if byte < 0x20 => return None,
                    _ => i += 1,
                }
            }
            None
        }
        fn value(&mut self) -> bool {
            self.ws();
            match self.bytes.get(self.pos).copied() {
                Some(b'{') => self.object(),
                Some(b'[') => self.array(),
                Some(b'"') => { let Some(end) = self.string_end(self.pos) else { return false }; self.pos = end; true }
                Some(_) => {
                    while self.pos < self.bytes.len()
                        && !matches!(self.bytes[self.pos], b',' | b']' | b'}')
                        && !self.bytes[self.pos].is_ascii_whitespace() { self.pos += 1; }
                    true
                }
                None => false,
            }
        }
        fn object(&mut self) -> bool {
            self.pos += 1; self.ws();
            if self.bytes.get(self.pos) == Some(&b'}') { self.pos += 1; return false; }
            let mut keys = std::collections::HashSet::<String>::new();
            loop {
                self.ws();
                let start = self.pos;
                let Some(end) = self.string_end(start) else { return false };
                let Ok(key) = serde_json::from_slice::<String>(&self.bytes[start..end]) else { return false };
                if !keys.insert(key) { return true; }
                self.pos = end; self.ws();
                if self.bytes.get(self.pos) != Some(&b':') { return false; }
                self.pos += 1;
                if !self.value() { return false; }
                self.ws();
                match self.bytes.get(self.pos) {
                    Some(b',') => self.pos += 1,
                    Some(b'}') => { self.pos += 1; return false; }
                    _ => return false,
                }
            }
        }
        fn array(&mut self) -> bool {
            self.pos += 1; self.ws();
            if self.bytes.get(self.pos) == Some(&b']') { self.pos += 1; return false; }
            loop {
                if !self.value() { return false; }
                self.ws();
                match self.bytes.get(self.pos) {
                    Some(b',') => self.pos += 1,
                    Some(b']') => { self.pos += 1; return false; }
                    _ => return false,
                }
            }
        }
    }
    Scanner { bytes, pos: 0 }.value()
}

fn validate_payload(payload: &[u8], expected_event_code: u16) -> Result<(), JournalError> {
    if payload.len() > JOURNAL_MAX_PAYLOAD_BYTES {
        return Err(JournalError::PayloadTooLarge);
    }
    let value: serde_json::Value =
        serde_json::from_slice(payload).map_err(|_| JournalError::InvalidPayloadJson)?;
    if has_duplicate_json_keys(payload) { return Err(JournalError::DuplicateJsonKey); }
    let object = value
        .as_object()
        .ok_or(JournalError::PayloadSchemaMismatch)?;
    let schema_version = object
        .get("schemaVersion")
        .and_then(serde_json::Value::as_u64);
    let event_code = object.get("eventCode").and_then(serde_json::Value::as_u64);
    if schema_version != Some(u64::from(JOURNAL_VERSION))
        || event_code != Some(u64::from(expected_event_code))
    {
        return Err(JournalError::PayloadSchemaMismatch);
    }
    Ok(())
}

fn serialize_record(
    input: &JournalRecordInput<'_>,
) -> Result<(Vec<u8>, [u8; JOURNAL_DIGEST_BYTES]), JournalError> {
    if input.sequence == 0
        || input.session_uuid.iter().all(|byte| *byte == 0)
        || input.canonical_payload.is_empty()
        || core::str::from_utf8(input.canonical_payload).is_err()
        || input
            .canonical_payload
            .first()
            .is_some_and(u8::is_ascii_whitespace)
        || input
            .canonical_payload
            .last()
            .is_some_and(u8::is_ascii_whitespace)
    {
        return Err(JournalError::InvalidRecord);
    }

    validate_payload(input.canonical_payload, input.record_type as u16)?;

    let payload_len =
        u32::try_from(input.canonical_payload.len()).map_err(|_| JournalError::LengthOverflow)?;
    let body_len = JOURNAL_MIN_BODY_BYTES
        .checked_add(input.canonical_payload.len())
        .ok_or(JournalError::LengthOverflow)?;
    let body_len_u32 = u32::try_from(body_len).map_err(|_| JournalError::LengthOverflow)?;
    let total_len = 4usize
        .checked_add(body_len)
        .ok_or(JournalError::LengthOverflow)?;
    u32::try_from(total_len).map_err(|_| JournalError::LengthOverflow)?;

    let mut bytes = Vec::<u8>::new();
    bytes
        .try_reserve_exact(total_len)
        .map_err(|_| JournalError::AllocationFailed)?;
    bytes.extend_from_slice(&body_len_u32.to_le_bytes());
    bytes.extend_from_slice(JOURNAL_MAGIC);
    bytes.extend_from_slice(&JOURNAL_VERSION.to_le_bytes());
    bytes.extend_from_slice(&(input.record_type as u16).to_le_bytes());
    bytes.extend_from_slice(&input.sequence.to_le_bytes());
    bytes.extend_from_slice(&input.monotonic_timestamp_ns.to_le_bytes());
    bytes.extend_from_slice(&input.session_uuid);
    bytes.extend_from_slice(&input.previous_digest);
    bytes.extend_from_slice(&payload_len.to_le_bytes());
    bytes.extend_from_slice(input.canonical_payload);

    let digest = calculate_record_digest(&input.previous_digest, &bytes[4..]);
    bytes.extend_from_slice(&digest);
    debug_assert_eq!(bytes.len(), total_len);
    Ok((bytes, digest))
}

/// SHA-256("SQJ1" || previous_digest || record_body_without_digest).
pub fn calculate_record_digest(
    previous_digest: &[u8; JOURNAL_DIGEST_BYTES],
    record_body_without_digest: &[u8],
) -> [u8; JOURNAL_DIGEST_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(JOURNAL_DIGEST_DOMAIN);
    hasher.update(previous_digest);
    hasher.update(record_body_without_digest);
    let result = hasher.finalize();
    let mut digest = [0u8; JOURNAL_DIGEST_BYTES];
    digest.copy_from_slice(&result);
    digest
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalVerificationStatus {
    Valid,
    TruncatedTail,
    Corrupt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalVerificationError {
    TruncatedLengthPrefix,
    TruncatedRecord,
    InvalidRecordLength,
    InvalidMagicOrVersion,
    InvalidRecordType,
    InvalidPayloadLength,
    InvalidUtf8Payload,
    DuplicateJsonKey,
    PayloadTooLarge,
    PayloadSchemaMismatch,
    SequenceMismatch,
    TimestampRegression,
    PreviousDigestMismatch,
    DigestMismatch,
    InvalidSessionId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalVerification {
    pub status: JournalVerificationStatus,
    pub error: Option<JournalVerificationError>,
    /// Bytes through the last fully verified record. Original tail bytes are never modified.
    pub valid_prefix_bytes: usize,
    pub last_sequence: u64,
    pub last_digest: [u8; JOURNAL_DIGEST_BYTES],
}

/// Scans without modifying/truncating input. A damaged tail must be preserved
/// by the caller and surfaced as a recovery/integrity event.
pub fn verify_journal(bytes: &[u8]) -> JournalVerification {
    let mut offset = 0usize;
    let mut expected_sequence = 1u64;
    let mut previous_digest = [0u8; JOURNAL_DIGEST_BYTES];
    let mut previous_timestamp: Option<u64> = None;

    while offset < bytes.len() {
        let remaining = bytes.len() - offset;
        if remaining < 4 {
            return verification(
                JournalVerificationStatus::TruncatedTail,
                Some(JournalVerificationError::TruncatedLengthPrefix),
                offset,
                expected_sequence - 1,
                previous_digest,
            );
        }
        let body_len = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        if body_len < JOURNAL_MIN_BODY_BYTES {
            return verification(
                JournalVerificationStatus::Corrupt,
                Some(JournalVerificationError::InvalidRecordLength),
                offset,
                expected_sequence - 1,
                previous_digest,
            );
        }
        let total_len = match body_len.checked_add(4) {
            Some(value) => value,
            None => {
                return verification(
                    JournalVerificationStatus::Corrupt,
                    Some(JournalVerificationError::InvalidRecordLength),
                    offset,
                    expected_sequence - 1,
                    previous_digest,
                );
            }
        };
        if total_len > remaining {
            return verification(
                JournalVerificationStatus::TruncatedTail,
                Some(JournalVerificationError::TruncatedRecord),
                offset,
                expected_sequence - 1,
                previous_digest,
            );
        }

        let body = &bytes[offset + 4..offset + total_len];
        if &body[..4] != JOURNAL_MAGIC || u16::from_le_bytes([body[4], body[5]]) != JOURNAL_VERSION
        {
            return verification(
                JournalVerificationStatus::Corrupt,
                Some(JournalVerificationError::InvalidMagicOrVersion),
                offset,
                expected_sequence - 1,
                previous_digest,
            );
        }
        if JournalRecordType::from_code(u16::from_le_bytes([body[6], body[7]])).is_none() {
            return verification(
                JournalVerificationStatus::Corrupt,
                Some(JournalVerificationError::InvalidRecordType),
                offset,
                expected_sequence - 1,
                previous_digest,
            );
        }
        let sequence = read_u64_le(body, 8);
        let timestamp = read_u64_le(body, 16);
        if previous_timestamp.is_some_and(|last| timestamp < last) {
            return verification(
                JournalVerificationStatus::Corrupt,
                Some(JournalVerificationError::TimestampRegression),
                offset,
                expected_sequence - 1,
                previous_digest,
            );
        }
        if sequence != expected_sequence {
            return verification(
                JournalVerificationStatus::Corrupt,
                Some(JournalVerificationError::SequenceMismatch),
                offset,
                expected_sequence - 1,
                previous_digest,
            );
        }
        if body[24..40].iter().all(|byte| *byte == 0) {
            return verification(
                JournalVerificationStatus::Corrupt,
                Some(JournalVerificationError::InvalidSessionId),
                offset,
                expected_sequence - 1,
                previous_digest,
            );
        }
        if body[40..72] != previous_digest[..] {
            return verification(
                JournalVerificationStatus::Corrupt,
                Some(JournalVerificationError::PreviousDigestMismatch),
                offset,
                expected_sequence - 1,
                previous_digest,
            );
        }
        let payload_len = read_u32_le(body, 72) as usize;
        if payload_len > JOURNAL_MAX_PAYLOAD_BYTES {
            return verification(
                JournalVerificationStatus::Corrupt,
                Some(JournalVerificationError::PayloadTooLarge),
                offset,
                expected_sequence - 1,
                previous_digest,
            );
        }
        if JOURNAL_MIN_BODY_BYTES.checked_add(payload_len) != Some(body.len()) {
            return verification(
                JournalVerificationStatus::Corrupt,
                Some(JournalVerificationError::InvalidPayloadLength),
                offset,
                expected_sequence - 1,
                previous_digest,
            );
        }
        let payload_end = 76 + payload_len;
        if core::str::from_utf8(&body[76..payload_end]).is_err() {
            return verification(
                JournalVerificationStatus::Corrupt,
                Some(JournalVerificationError::InvalidUtf8Payload),
                offset,
                expected_sequence - 1,
                previous_digest,
            );
        }
        if validate_payload(&body[76..payload_end], read_u16_le(body, 6)) == Err(JournalError::DuplicateJsonKey) {
            return verification(JournalVerificationStatus::Corrupt, Some(JournalVerificationError::DuplicateJsonKey), offset, expected_sequence - 1, previous_digest);
        }
        if validate_payload(&body[76..payload_end], read_u16_le(body, 6)).is_err() {
            return verification(
                JournalVerificationStatus::Corrupt,
                Some(JournalVerificationError::PayloadSchemaMismatch),
                offset,
                expected_sequence - 1,
                previous_digest,
            );
        }
        let expected_digest = calculate_record_digest(&previous_digest, &body[..body.len() - 32]);
        let mut stored_digest = [0u8; 32];
        stored_digest.copy_from_slice(&body[body.len() - 32..]);
        if expected_digest != stored_digest {
            return verification(
                JournalVerificationStatus::Corrupt,
                Some(JournalVerificationError::DigestMismatch),
                offset,
                expected_sequence - 1,
                previous_digest,
            );
        }

        previous_digest = stored_digest;
        previous_timestamp = Some(timestamp);
        offset += total_len;
        if sequence == u64::MAX {
            let status = if offset == bytes.len() {
                JournalVerificationStatus::Valid
            } else {
                JournalVerificationStatus::Corrupt
            };
            let error = if status == JournalVerificationStatus::Valid {
                None
            } else {
                Some(JournalVerificationError::SequenceMismatch)
            };
            return verification(status, error, offset, sequence, previous_digest);
        }
        expected_sequence = sequence + 1;
    }

    verification(
        JournalVerificationStatus::Valid,
        None,
        offset,
        expected_sequence - 1,
        previous_digest,
    )
}

fn read_u16_le(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64_le(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

fn verification(
    status: JournalVerificationStatus,
    error: Option<JournalVerificationError>,
    valid_prefix_bytes: usize,
    last_sequence: u64,
    last_digest: [u8; JOURNAL_DIGEST_BYTES],
) -> JournalVerification {
    JournalVerification {
        status,
        error,
        valid_prefix_bytes,
        last_sequence,
        last_digest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MemorySink {
        bytes: Vec<u8>,
        sync_count: usize,
        fail_sync: bool,
        fail_write_after: Option<usize>,
    }

    impl JournalSink for MemorySink {
        fn append_bytes(&mut self, record_bytes: &[u8]) -> Result<(), JournalSinkError> {
            if let Some(limit) = self.fail_write_after {
                let partial_len = limit.min(record_bytes.len());
                self.bytes.extend_from_slice(&record_bytes[..partial_len]);
                return Err(JournalSinkError::WriteFailed);
            }
            self.bytes.extend_from_slice(record_bytes);
            Ok(())
        }

        fn sync(&mut self) -> Result<(), JournalSinkError> {
            self.sync_count += 1;
            if self.fail_sync {
                Err(JournalSinkError::SyncFailed)
            } else {
                Ok(())
            }
        }
    }

    fn input(sequence: u64, previous_digest: [u8; 32]) -> JournalRecordInput<'static> {
        JournalRecordInput {
            sequence,
            monotonic_timestamp_ns: sequence * 10,
            session_uuid: [0x22; 16],
            record_type: JournalRecordType::CaptureStarted,
            canonical_payload: br#"{"captureEpoch":"1","eventCode":2,"schemaVersion":1}"#,
            previous_digest,
        }
    }

    #[test]
    fn writer_and_verifier_reject_duplicate_json_keys() {
        let duplicate = br#"{"captureEpoch":"1","eventCode":2,"eventCode":2,"schemaVersion":1}"#;
        let mut record = input(1, [0; 32]);
        record.canonical_payload = duplicate;
        let mut writer = JournalWriter::new(MemorySink::default());
        assert_eq!(writer.append(record), Err(JournalError::DuplicateJsonKey));

        // A validly framed record with a matching digest cannot legitimize
        // ambiguous JSON metadata.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((JOURNAL_MIN_BODY_BYTES + duplicate.len()) as u32).to_le_bytes());
        bytes.extend_from_slice(JOURNAL_MAGIC);
        bytes.extend_from_slice(&JOURNAL_VERSION.to_le_bytes());
        bytes.extend_from_slice(&(JournalRecordType::CaptureStarted as u16).to_le_bytes());
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&10u64.to_le_bytes());
        bytes.extend_from_slice(&[0x22; 16]);
        bytes.extend_from_slice(&[0; 32]);
        bytes.extend_from_slice(&(duplicate.len() as u32).to_le_bytes());
        bytes.extend_from_slice(duplicate);
        let digest = calculate_record_digest(&[0; 32], &bytes[4..]);
        bytes.extend_from_slice(&digest);
        assert_eq!(verify_journal(&bytes).error, Some(JournalVerificationError::DuplicateJsonKey));
    }

    #[test]
    fn durable_append_verifies_and_chains_records() {
        let mut writer = JournalWriter::new(MemorySink::default());
        let first = writer.append(input(1, [0; 32])).unwrap();
        let second = writer.append(input(2, first.digest)).unwrap();
        let sink = writer.into_sink();
        assert_eq!(sink.sync_count, 2);
        let verified = verify_journal(&sink.bytes);
        assert_eq!(verified.status, JournalVerificationStatus::Valid);
        assert_eq!(verified.last_sequence, 2);
        assert_eq!(verified.last_digest, second.digest);
    }

    #[test]
    fn verifier_reports_truncated_tail_without_mutating_source() {
        let mut writer = JournalWriter::new(MemorySink::default());
        writer.append(input(1, [0; 32])).unwrap();
        let mut bytes = writer.into_sink().bytes;
        let valid_len = bytes.len();
        bytes.extend_from_slice(&[0x10, 0x00]);
        let verified = verify_journal(&bytes);
        assert_eq!(verified.status, JournalVerificationStatus::TruncatedTail);
        assert_eq!(verified.valid_prefix_bytes, valid_len);
        assert_eq!(bytes.len(), valid_len + 2);
    }

    #[test]
    fn verifier_detects_payload_tampering() {
        let mut writer = JournalWriter::new(MemorySink::default());
        writer.append(input(1, [0; 32])).unwrap();
        let mut bytes = writer.into_sink().bytes;
        // Find the exact schema-neutral JSON value instead of relying on a
        // fragile serialized-byte offset. Keep the payload valid so verification
        // reaches the digest check rather than failing schema validation.
        let payload = b"\"captureEpoch\":\"1\"";
        let payload_offset = bytes[4 + 76..]
            .windows(payload.len())
            .position(|window| window == payload)
            .expect("fixture contains captureEpoch value");
        let value_offset = 4 + 76 + payload_offset + payload.len() - 2;
        assert_eq!(bytes[value_offset], b'1');
        bytes[value_offset] = b'0';
        assert_eq!(bytes[value_offset], b'0');
        assert_eq!(
            verify_journal(&bytes).error,
            Some(JournalVerificationError::DigestMismatch)
        );
    }

    #[test]
    fn writer_rejects_wrong_sequence_and_stops_after_sync_failure() {
        let mut writer = JournalWriter::new(MemorySink::default());
        assert_eq!(
            writer.append(input(2, [0; 32])),
            Err(JournalError::SequenceMismatch)
        );

        let failed_sink = MemorySink {
            fail_sync: true,
            ..MemorySink::default()
        };
        let mut failed_writer = JournalWriter::new(failed_sink);
        assert_eq!(
            failed_writer.append(input(1, [0; 32])),
            Err(JournalError::SinkSyncFailed)
        );
        assert_eq!(
            failed_writer.append(input(1, [0; 32])),
            Err(JournalError::WriterTerminal)
        );
    }
    #[test]
    fn writer_latches_partial_write_and_recovery_detects_torn_tail() {
        let failing_sink = MemorySink {
            fail_write_after: Some(17),
            ..MemorySink::default()
        };
        let mut writer = JournalWriter::new(failing_sink);
        assert_eq!(
            writer.append(input(1, [0; 32])),
            Err(JournalError::SinkAppendFailed)
        );
        assert_eq!(
            writer.append(input(1, [0; 32])),
            Err(JournalError::WriterTerminal)
        );
        let sink = writer.into_sink();
        let verification = verify_journal(&sink.bytes);
        assert_eq!(
            verification.status,
            JournalVerificationStatus::TruncatedTail
        );
        assert_eq!(verification.valid_prefix_bytes, 0);
    }

    #[test]
    fn writer_rejects_invalid_json_and_wrong_event_schema() {
        let mut writer = JournalWriter::new(MemorySink::default());
        let mut invalid_json = input(1, [0; 32]);
        invalid_json.canonical_payload = br#"{"schemaVersion":1,"eventCode":2"#;
        assert_eq!(
            writer.append(invalid_json),
            Err(JournalError::InvalidPayloadJson)
        );

        let mut wrong_schema = input(1, [0; 32]);
        wrong_schema.canonical_payload = br#"{"eventCode":3,"schemaVersion":1}"#;
        assert_eq!(
            writer.append(wrong_schema),
            Err(JournalError::PayloadSchemaMismatch)
        );
    }

    #[test]
    fn verifier_rejects_schema_mismatch_even_with_recomputed_digest() {
        let mut writer = JournalWriter::new(MemorySink::default());
        writer.append(input(1, [0; 32])).unwrap();
        let mut bytes = writer.into_sink().bytes;
        bytes[4 + 76 + 32] = b'3'; // eventCode changes 2 -> 3, preserving JSON validity
        let digest_start = bytes.len() - JOURNAL_DIGEST_BYTES;
        let digest = calculate_record_digest(&[0; 32], &bytes[4..digest_start]);
        bytes[digest_start..].copy_from_slice(&digest);
        assert_eq!(
            verify_journal(&bytes).error,
            Some(JournalVerificationError::PayloadSchemaMismatch)
        );
    }

    #[test]
    fn writer_rejects_oversized_metadata_before_serialization() {
        let oversized = format!(
            "{{\"eventCode\":2,\"schemaVersion\":1,\"padding\":\"{}\"}}",
            "x".repeat(JOURNAL_MAX_PAYLOAD_BYTES)
        );
        let mut record = input(1, [0; 32]);
        record.canonical_payload = oversized.as_bytes();
        let mut writer = JournalWriter::new(MemorySink::default());
        assert_eq!(writer.append(record), Err(JournalError::PayloadTooLarge));
    }

    #[test]
    fn writer_rejects_monotonic_timestamp_regression() {
        let mut writer = JournalWriter::new(MemorySink::default());
        let first = writer.append(input(1, [0; 32])).unwrap();
        let mut second = input(2, first.digest);
        second.monotonic_timestamp_ns = 5;
        assert_eq!(
            writer.append(second),
            Err(JournalError::TimestampRegression)
        );
    }
}
