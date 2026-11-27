//! Portable SQJ signature-anchor validation and signing-preimage construction.
//! ECDSA execution is supplied by the platform crypto provider; this module
//! enforces canonical metadata, retained-key binding, and byte-exact preimage.
use crate::anchor_registry::{
    ANCHOR_KEY_ID_BYTES, ANCHOR_KEY_ID_PREFIX, AnchorKeyRegistryStatus, anchor_public_key_id,
    verify_anchor_key_registry,
};
use std::convert::TryFrom;

pub const JOURNAL_ANCHOR_DOMAIN: &[u8] = b"SQREC-JOURNAL-ANCHOR-V1";
pub const JOURNAL_ANCHOR_SIGNATURE_ID: &str = "ecdsa-p256-sha256-v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalSignatureAnchor {
    pub format_version: u16,
    pub sequence: u64,
    pub digest: [u8; 32],
    pub signature_algorithm_id: String,
    pub signing_key_id: String,
    pub signature_der: Vec<u8>,
    pub authentication_epoch: u64,
    pub monotonic_timestamp_ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorSigningPayloadError {
    InvalidSequence,
    InvalidKeyId,
    LengthOverflow,
    AllocationFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorCryptoProviderError {
    Unsupported,
    ProviderFailure,
}

pub trait P256Sha256SignatureProvider {
    fn verify(
        &self,
        public_key_spki_der: &[u8],
        message: &[u8],
        signature_der: &[u8],
    ) -> Result<bool, AnchorCryptoProviderError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalAnchorVerificationResult {
    Valid,
    InvalidMetadata,
    InvalidKeyRegistry,
    KeyNotFound,
    KeyIdMismatch,
    InvalidSignature,
    UnsupportedAlgorithm,
    CryptoProviderFailure,
}

pub fn verify_journal_anchor<P: P256Sha256SignatureProvider>(
    anchor: &JournalSignatureAnchor,
    registry_bytes: &[u8],
    provider: &P,
) -> JournalAnchorVerificationResult {
    if anchor.format_version != 1
        || anchor.sequence == 0
        || !is_anchor_key_id(&anchor.signing_key_id)
        || anchor.signature_der.is_empty()
        || anchor.signature_der.len() > 80
    {
        return JournalAnchorVerificationResult::InvalidMetadata;
    }
    if anchor.signature_algorithm_id != JOURNAL_ANCHOR_SIGNATURE_ID {
        return JournalAnchorVerificationResult::UnsupportedAlgorithm;
    }
    let registry = verify_anchor_key_registry(registry_bytes);
    if registry.status != AnchorKeyRegistryStatus::Valid
        || registry.valid_prefix_bytes != registry_bytes.len()
    {
        return JournalAnchorVerificationResult::InvalidKeyRegistry;
    }
    let Some(key) = registry
        .retained_keys
        .iter()
        .find(|r| r.key_id == anchor.signing_key_id)
    else {
        return JournalAnchorVerificationResult::KeyNotFound;
    };
    if anchor_public_key_id(&key.encoded_public_key) != anchor.signing_key_id {
        return JournalAnchorVerificationResult::KeyIdMismatch;
    }
    let payload = match journal_anchor_signing_payload(
        anchor.sequence,
        &anchor.digest,
        &anchor.signing_key_id,
        anchor.authentication_epoch,
        anchor.monotonic_timestamp_ns,
    ) {
        Ok(bytes) => bytes,
        Err(_) => return JournalAnchorVerificationResult::InvalidMetadata,
    };
    match provider.verify(&key.encoded_public_key, &payload, &anchor.signature_der) {
        Ok(true) => JournalAnchorVerificationResult::Valid,
        Ok(false) => JournalAnchorVerificationResult::InvalidSignature,
        Err(AnchorCryptoProviderError::Unsupported) => {
            JournalAnchorVerificationResult::UnsupportedAlgorithm
        }
        Err(AnchorCryptoProviderError::ProviderFailure) => {
            JournalAnchorVerificationResult::CryptoProviderFailure
        }
    }
}

/// Matches the Android signer: domain || seq:u64le || digest:32 ||
/// keyIdLen:u16le || keyId:utf8 || authEpoch:u64le || monotonicNs:u64le.
pub fn journal_anchor_signing_payload(
    sequence: u64,
    digest: &[u8; 32],
    key_id: &str,
    auth_epoch: u64,
    monotonic_ns: u64,
) -> Result<Vec<u8>, AnchorSigningPayloadError> {
    if sequence == 0 {
        return Err(AnchorSigningPayloadError::InvalidSequence);
    }
    if !is_anchor_key_id(key_id) {
        return Err(AnchorSigningPayloadError::InvalidKeyId);
    }
    let id = key_id.as_bytes();
    let id_len = u16::try_from(id.len()).map_err(|_| AnchorSigningPayloadError::LengthOverflow)?;
    let mut payload = Vec::new();
    payload
        .try_reserve(JOURNAL_ANCHOR_DOMAIN.len() + 8 + 32 + 2 + id.len() + 16)
        .map_err(|_| AnchorSigningPayloadError::AllocationFailed)?;
    payload.extend_from_slice(JOURNAL_ANCHOR_DOMAIN);
    payload.extend_from_slice(&sequence.to_le_bytes());
    payload.extend_from_slice(digest);
    payload.extend_from_slice(&id_len.to_le_bytes());
    payload.extend_from_slice(id);
    payload.extend_from_slice(&auth_epoch.to_le_bytes());
    payload.extend_from_slice(&monotonic_ns.to_le_bytes());
    Ok(payload)
}

fn is_anchor_key_id(id: &str) -> bool {
    id.len() == ANCHOR_KEY_ID_BYTES
        && id.starts_with(ANCHOR_KEY_ID_PREFIX)
        && id[ANCHOR_KEY_ID_PREFIX.len()..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anchor_registry::AnchorKeyRegistryWriter;
    use crate::{JournalSink, JournalSinkError};
    use std::io::Write;

    #[derive(Default)]
    struct Sink(Vec<u8>);
    impl JournalSink for Sink {
        fn append_bytes(&mut self, bytes: &[u8]) -> Result<(), JournalSinkError> {
            self.0
                .write_all(bytes)
                .map_err(|_| JournalSinkError::WriteFailed)
        }
        fn sync(&mut self) -> Result<(), JournalSinkError> {
            Ok(())
        }
    }
    struct Accept;
    impl P256Sha256SignatureProvider for Accept {
        fn verify(&self, _: &[u8], _: &[u8], _: &[u8]) -> Result<bool, AnchorCryptoProviderError> {
            Ok(true)
        }
    }

    fn make_registry() -> (Vec<u8>, String) {
        let der = vec![0x30, 0x04, 0x02, 0x02, 0x55, 0x66];
        let mut writer = AnchorKeyRegistryWriter::new(Sink::default());
        let key = writer.append_key(&der).unwrap();
        (writer.into_sink().0, key.key_id)
    }

    #[test]
    fn preimage_matches_android_little_endian_contract() {
        let key = anchor_public_key_id(&[0x30, 0x01]);
        let digest = [0xab; 32];
        let got = journal_anchor_signing_payload(7, &digest, &key, 9, 11).unwrap();
        let mut expected = JOURNAL_ANCHOR_DOMAIN.to_vec();
        expected.extend_from_slice(&7u64.to_le_bytes());
        expected.extend_from_slice(&digest);
        expected.extend_from_slice(&(ANCHOR_KEY_ID_BYTES as u16).to_le_bytes());
        expected.extend_from_slice(key.as_bytes());
        expected.extend_from_slice(&9u64.to_le_bytes());
        expected.extend_from_slice(&11u64.to_le_bytes());
        assert_eq!(got, expected);
    }

    #[test]
    fn binds_anchor_to_retained_key_and_metadata() {
        let (registry, key_id) = make_registry();
        let anchor = JournalSignatureAnchor {
            format_version: 1,
            sequence: 4,
            digest: [0x42; 32],
            signature_algorithm_id: JOURNAL_ANCHOR_SIGNATURE_ID.into(),
            signing_key_id: key_id,
            signature_der: vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01],
            authentication_epoch: 2,
            monotonic_timestamp_ns: 99,
        };
        assert_eq!(
            verify_journal_anchor(&anchor, &registry, &Accept),
            JournalAnchorVerificationResult::Valid
        );
        let mut changed = anchor.clone();
        changed.sequence = 0;
        assert_eq!(
            verify_journal_anchor(&changed, &registry, &Accept),
            JournalAnchorVerificationResult::InvalidMetadata
        );
    }
}
