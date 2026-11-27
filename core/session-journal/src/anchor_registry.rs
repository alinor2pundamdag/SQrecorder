//! Append-only, hash-chained public-key registry for signed SQJ anchors.
//!
//! This registry preserves historical public keys across signer rotation. Its
//! integrity chain detects partial/reordered records; the storage adapter must
//! provide durable append+sync and protect the registry file against replacement.
//! A hash chain alone is not an external trust root or backup/restore signature.
use crate::JournalSink;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub const ANCHOR_KEY_REGISTRY_MAGIC: &[u8; 4] = b"SQAK";
pub const ANCHOR_KEY_REGISTRY_VERSION: u16 = 1;
pub const ANCHOR_KEY_ID_PREFIX: &str = "ecdsa-p256-sha256-v1-";
pub const ANCHOR_KEY_ID_BYTES: usize = 53;
pub const ANCHOR_KEY_MAX_DER_BYTES: usize = 2_048;
pub const ANCHOR_KEY_REGISTRY_MAX_BYTES: usize = 4 * 1024 * 1024;
pub const ANCHOR_KEY_REGISTRY_MAX_RECORDS: usize = 4_096;
const RECORD_DIGEST_BYTES: usize = 32;
const ZERO_DIGEST: [u8; 32] = [0; 32];
const RECORD_DOMAIN: &[u8] = b"SQREC-ANCHOR-KEY-REGISTRY-V1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorKeyRegistryError {
    InvalidRecord,
    InvalidKeyId,
    InvalidPublicKeyEncoding,
    DuplicateKeyId,
    InvalidMagic,
    UnsupportedVersion,
    SequenceMismatch,
    PreviousDigestMismatch,
    DigestMismatch,
    LengthOverflow,
    AllocationFailed,
    RegistryTooLarge,
    RecordLimitReached,
    RecoveryRequired,
    SinkAppendFailed,
    SinkSyncFailed,
    WriterTerminal,
    SequenceExhausted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedAnchorPublicKey {
    pub sequence: u64,
    pub key_id: String,
    /// Provider-encoded public key (Android X.509 SubjectPublicKeyInfo DER).
    pub encoded_public_key: Vec<u8>,
    pub record_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorKeyRegistryStatus {
    Valid,
    TruncatedTail,
    Corrupt,
}

pub struct AnchorKeyRegistryVerification {
    pub status: AnchorKeyRegistryStatus,
    pub valid_prefix_bytes: usize,
    pub last_sequence: u64,
    pub last_digest: [u8; 32],
    pub retained_keys: Vec<RetainedAnchorPublicKey>,
    pub error: Option<AnchorKeyRegistryError>,
}

pub struct AnchorKeyRegistryWriter<S: JournalSink> {
    sink: S,
    next_sequence: Option<u64>,
    previous_digest: [u8; 32],
    key_ids: HashSet<String>,
    terminal: bool,
    bytes_written: usize,
}

impl<S: JournalSink> AnchorKeyRegistryWriter<S> {
    pub fn new(sink: S) -> Self {
        Self {
            sink,
            next_sequence: Some(1),
            previous_digest: ZERO_DIGEST,
            key_ids: HashSet::new(),
            terminal: false,
            bytes_written: 0,
        }
    }

    /// Resume only from a fully verified registry; caller positions sink at EOF.
    pub fn resume(sink: S, existing: &[u8]) -> Result<Self, AnchorKeyRegistryError> {
        let verified = verify_anchor_key_registry(existing);
        if verified.status != AnchorKeyRegistryStatus::Valid
            || verified.valid_prefix_bytes != existing.len()
        {
            return Err(AnchorKeyRegistryError::RecoveryRequired);
        }
        let mut key_ids = HashSet::new();
        for record in &verified.retained_keys {
            if !key_ids.insert(record.key_id.clone()) {
                return Err(AnchorKeyRegistryError::DuplicateKeyId);
            }
        }
        Ok(Self {
            sink,
            next_sequence: verified.last_sequence.checked_add(1),
            previous_digest: verified.last_digest,
            key_ids,
            terminal: false,
            bytes_written: existing.len(),
        })
    }

    /// Persist a public key before creating anchors with it. Key records are unique;
    /// rotation appends a new key and never overwrites/removes historical entries.
    pub fn append_key(
        &mut self,
        encoded_public_key: &[u8],
    ) -> Result<RetainedAnchorPublicKey, AnchorKeyRegistryError> {
        if self.terminal {
            return Err(AnchorKeyRegistryError::WriterTerminal);
        }
        let sequence = self
            .next_sequence
            .ok_or(AnchorKeyRegistryError::SequenceExhausted)?;
        if self.key_ids.len() >= ANCHOR_KEY_REGISTRY_MAX_RECORDS {
            return Err(AnchorKeyRegistryError::RecordLimitReached);
        }
        if encoded_public_key.is_empty()
            || encoded_public_key.len() > ANCHOR_KEY_MAX_DER_BYTES
            || encoded_public_key[0] != 0x30
        {
            return Err(AnchorKeyRegistryError::InvalidPublicKeyEncoding);
        }
        let key_id = anchor_public_key_id(encoded_public_key);
        if !is_anchor_key_id(&key_id) {
            return Err(AnchorKeyRegistryError::InvalidKeyId);
        }
        if self.key_ids.contains(&key_id) {
            return Err(AnchorKeyRegistryError::DuplicateKeyId);
        }
        let bytes = serialize_registry_record(
            sequence,
            &key_id,
            encoded_public_key,
            &self.previous_digest,
        )?;
        if self
            .bytes_written
            .checked_add(bytes.len())
            .is_none_or(|n| n > ANCHOR_KEY_REGISTRY_MAX_BYTES)
        {
            return Err(AnchorKeyRegistryError::RegistryTooLarge);
        }
        let record_digest = bytes[bytes.len() - RECORD_DIGEST_BYTES..]
            .try_into()
            .map_err(|_| AnchorKeyRegistryError::InvalidRecord)?;
        if self.sink.append_bytes(&bytes).is_err() {
            self.terminal = true;
            return Err(AnchorKeyRegistryError::SinkAppendFailed);
        }
        if self.sink.sync().is_err() {
            self.terminal = true;
            return Err(AnchorKeyRegistryError::SinkSyncFailed);
        }
        self.key_ids.insert(key_id.clone());
        self.previous_digest = record_digest;
        self.next_sequence = sequence.checked_add(1);
        self.bytes_written += bytes.len();
        Ok(RetainedAnchorPublicKey {
            sequence,
            key_id,
            encoded_public_key: encoded_public_key.to_vec(),
            record_digest,
        })
    }

    pub fn into_sink(self) -> S {
        self.sink
    }
}

/// Fingerprint scheme shared with the Android signer: first 16 bytes of SHA-256
/// over the exact encoded public-key bytes, lowercase hexadecimal.
pub fn anchor_public_key_id(encoded_public_key: &[u8]) -> String {
    let digest = Sha256::digest(encoded_public_key);
    let mut id = String::with_capacity(ANCHOR_KEY_ID_BYTES);
    id.push_str(ANCHOR_KEY_ID_PREFIX);
    for byte in digest.iter().take(16) {
        use std::fmt::Write as _;
        let _ = write!(id, "{byte:02x}");
    }
    id
}

pub fn verify_anchor_key_registry(bytes: &[u8]) -> AnchorKeyRegistryVerification {
    let mut result = AnchorKeyRegistryVerification {
        status: AnchorKeyRegistryStatus::Valid,
        valid_prefix_bytes: 0,
        last_sequence: 0,
        last_digest: ZERO_DIGEST,
        retained_keys: Vec::new(),
        error: None,
    };
    if bytes.len() > ANCHOR_KEY_REGISTRY_MAX_BYTES {
        result.status = AnchorKeyRegistryStatus::Corrupt;
        result.error = Some(AnchorKeyRegistryError::RegistryTooLarge);
        return result;
    }
    let mut ids = HashSet::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        if bytes.len() - offset < 4 {
            result.status = AnchorKeyRegistryStatus::TruncatedTail;
            break;
        }
        let body_len = read_u32_le(bytes, offset) as usize;
        let Some(total_len) = body_len.checked_add(4) else {
            result.status = AnchorKeyRegistryStatus::Corrupt;
            result.error = Some(AnchorKeyRegistryError::LengthOverflow);
            break;
        };
        if !(84..=4 + 2 + 8 + 2 + 4 + 32 + ANCHOR_KEY_ID_BYTES + ANCHOR_KEY_MAX_DER_BYTES + 32)
            .contains(&body_len)
        {
            result.status = AnchorKeyRegistryStatus::Corrupt;
            result.error = Some(AnchorKeyRegistryError::InvalidRecord);
            break;
        }
        if total_len > bytes.len() - offset {
            result.status = AnchorKeyRegistryStatus::TruncatedTail;
            break;
        }
        let record = &bytes[offset + 4..offset + total_len];
        let parsed = parse_registry_record(record, result.last_sequence, &result.last_digest);
        let key = match parsed {
            Ok(key) => key,
            Err(error) => {
                result.status = AnchorKeyRegistryStatus::Corrupt;
                result.error = Some(error);
                break;
            }
        };
        if !ids.insert(key.key_id.clone()) {
            result.status = AnchorKeyRegistryStatus::Corrupt;
            result.error = Some(AnchorKeyRegistryError::DuplicateKeyId);
            break;
        }
        result.last_sequence = key.sequence;
        result.last_digest = key.record_digest;
        result.retained_keys.push(key);
        if result.retained_keys.len() > ANCHOR_KEY_REGISTRY_MAX_RECORDS {
            result.status = AnchorKeyRegistryStatus::Corrupt;
            result.error = Some(AnchorKeyRegistryError::RecordLimitReached);
            result.retained_keys.pop();
            break;
        }
        offset += total_len;
        result.valid_prefix_bytes = offset;
    }
    result
}

fn serialize_registry_record(
    sequence: u64,
    key_id: &str,
    public_key: &[u8],
    previous_digest: &[u8; 32],
) -> Result<Vec<u8>, AnchorKeyRegistryError> {
    let id_len = u16::try_from(key_id.len()).map_err(|_| AnchorKeyRegistryError::LengthOverflow)?;
    let key_len =
        u32::try_from(public_key.len()).map_err(|_| AnchorKeyRegistryError::LengthOverflow)?;
    let body_without_digest = 4usize + 2 + 8 + 2 + 4 + 32 + key_id.len() + public_key.len();
    let body_len = body_without_digest
        .checked_add(32)
        .ok_or(AnchorKeyRegistryError::LengthOverflow)?;
    let body_len_u32 =
        u32::try_from(body_len).map_err(|_| AnchorKeyRegistryError::LengthOverflow)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve(body_len + 4)
        .map_err(|_| AnchorKeyRegistryError::AllocationFailed)?;
    bytes.extend_from_slice(&body_len_u32.to_le_bytes());
    bytes.extend_from_slice(ANCHOR_KEY_REGISTRY_MAGIC);
    bytes.extend_from_slice(&ANCHOR_KEY_REGISTRY_VERSION.to_le_bytes());
    bytes.extend_from_slice(&sequence.to_le_bytes());
    bytes.extend_from_slice(&id_len.to_le_bytes());
    bytes.extend_from_slice(&key_len.to_le_bytes());
    bytes.extend_from_slice(previous_digest);
    bytes.extend_from_slice(key_id.as_bytes());
    bytes.extend_from_slice(public_key);
    let digest = registry_digest(&bytes[4..]);
    bytes.extend_from_slice(&digest);
    Ok(bytes)
}

fn parse_registry_record(
    record: &[u8],
    previous_sequence: u64,
    previous_digest: &[u8; 32],
) -> Result<RetainedAnchorPublicKey, AnchorKeyRegistryError> {
    if record.len() < 84 || record.get(..4) != Some(&ANCHOR_KEY_REGISTRY_MAGIC[..]) {
        return Err(AnchorKeyRegistryError::InvalidMagic);
    }
    if read_u16_le(record, 4) != ANCHOR_KEY_REGISTRY_VERSION {
        return Err(AnchorKeyRegistryError::UnsupportedVersion);
    }
    let sequence = read_u64_le(record, 6);
    if sequence
        != previous_sequence
            .checked_add(1)
            .ok_or(AnchorKeyRegistryError::SequenceExhausted)?
    {
        return Err(AnchorKeyRegistryError::SequenceMismatch);
    }
    let id_len = read_u16_le(record, 14) as usize;
    let key_len = read_u32_le(record, 16) as usize;
    if id_len != ANCHOR_KEY_ID_BYTES || key_len == 0 || key_len > ANCHOR_KEY_MAX_DER_BYTES {
        return Err(AnchorKeyRegistryError::InvalidRecord);
    }
    let expected_len = 52usize
        .checked_add(id_len)
        .and_then(|n| n.checked_add(key_len))
        .and_then(|n| n.checked_add(32))
        .ok_or(AnchorKeyRegistryError::LengthOverflow)?;
    if record.len() != expected_len {
        return Err(AnchorKeyRegistryError::InvalidRecord);
    }
    if record[20..52] != previous_digest[..] {
        return Err(AnchorKeyRegistryError::PreviousDigestMismatch);
    }
    let id_end = 52 + id_len;
    let key_end = id_end + key_len;
    let key_id = std::str::from_utf8(&record[52..id_end])
        .map_err(|_| AnchorKeyRegistryError::InvalidKeyId)?
        .to_owned();
    let public_key = record[id_end..key_end].to_vec();
    if public_key.first() != Some(&0x30) || anchor_public_key_id(&public_key) != key_id {
        return Err(AnchorKeyRegistryError::InvalidPublicKeyEncoding);
    }
    if !is_anchor_key_id(&key_id) {
        return Err(AnchorKeyRegistryError::InvalidKeyId);
    }
    let expected_digest = registry_digest(&record[..key_end]);
    if record[key_end..] != expected_digest[..] {
        return Err(AnchorKeyRegistryError::DigestMismatch);
    }
    Ok(RetainedAnchorPublicKey {
        sequence,
        key_id,
        encoded_public_key: public_key,
        record_digest: expected_digest,
    })
}

fn registry_digest(record_without_digest: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RECORD_DOMAIN);
    hasher.update(record_without_digest);
    hasher.finalize().into()
}

fn is_anchor_key_id(id: &str) -> bool {
    id.len() == ANCHOR_KEY_ID_BYTES
        && id.starts_with(ANCHOR_KEY_ID_PREFIX)
        && id[ANCHOR_KEY_ID_PREFIX.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn read_u16_le(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}
fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("bounded record"),
    )
}
fn read_u64_le(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("bounded record"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::JournalSinkError;
    use std::io::Write;

    #[derive(Default)]
    struct MemorySink(Vec<u8>);
    impl JournalSink for MemorySink {
        fn append_bytes(&mut self, bytes: &[u8]) -> Result<(), JournalSinkError> {
            self.0
                .write_all(bytes)
                .map_err(|_| JournalSinkError::WriteFailed)
        }
        fn sync(&mut self) -> Result<(), JournalSinkError> {
            Ok(())
        }
    }

    fn der(seed: u8) -> Vec<u8> {
        vec![0x30, 0x04, 0x02, 0x02, seed, seed]
    }

    #[test]
    fn append_verify_resume_and_retain_historical_keys() {
        let mut writer = AnchorKeyRegistryWriter::new(MemorySink::default());
        let first = writer.append_key(&der(1)).unwrap();
        let second = writer.append_key(&der(2)).unwrap();
        assert_eq!(first.sequence, 1);
        assert_eq!(second.sequence, 2);
        let bytes = writer.into_sink().0;
        let verified = verify_anchor_key_registry(&bytes);
        assert_eq!(verified.status, AnchorKeyRegistryStatus::Valid);
        assert_eq!(verified.retained_keys.len(), 2);
        assert_eq!(verified.last_sequence, 2);
        let mut resumed =
            AnchorKeyRegistryWriter::resume(MemorySink(bytes.clone()), &bytes).unwrap();
        assert_eq!(resumed.append_key(&der(3)).unwrap().sequence, 3);
    }

    #[test]
    fn rejects_duplicate_keys_tampering_and_truncated_tail() {
        let mut writer = AnchorKeyRegistryWriter::new(MemorySink::default());
        writer.append_key(&der(4)).unwrap();
        let bytes = writer.into_sink().0;
        let mut resumed =
            AnchorKeyRegistryWriter::resume(MemorySink(bytes.clone()), &bytes).unwrap();
        assert_eq!(
            resumed.append_key(&der(4)),
            Err(AnchorKeyRegistryError::DuplicateKeyId)
        );
        let mut tampered = bytes.clone();
        tampered[60] ^= 0x01;
        assert_eq!(
            verify_anchor_key_registry(&tampered).status,
            AnchorKeyRegistryStatus::Corrupt
        );
        assert_eq!(
            verify_anchor_key_registry(&bytes[..bytes.len() - 1]).status,
            AnchorKeyRegistryStatus::TruncatedTail
        );
    }
}
