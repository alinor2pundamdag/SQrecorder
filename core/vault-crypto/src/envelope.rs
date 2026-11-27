//! Explicit SQVE v1 serialization and chunk writer.
//!
//! This module writes a caller-provided temporary sink. The platform storage
//! adapter is responsible for fsync, atomic rename, directory fsync, and
//! appending the durable journal commit after promotion.
use std::io::{Read, Seek, SeekFrom, Write};

use sha2::{Digest, Sha256};

use crate::{
    GCM_TAG_BYTES, VaultCryptoError, VaultFileKey, encrypt_chunk_in_place, nonce_for_chunk,
};

pub const SQVE_HEADER_BYTES: usize = 64;
pub const SQVE_FOOTER_BYTES: usize = 56;
pub const SQVE_CHUNK_BYTES: usize = 1_048_576;
pub const SQVE_MAX_HEADER_BYTES: usize = u16::MAX as usize;
pub const SQVE_FILE_KEY_ID_MAX_BYTES: usize = 128;
pub const SQVE_RECIPIENT_ID_MAX_BYTES: usize = 128;
const AAD_DOMAIN: &[u8; 9] = b"SQVE-AAD1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum WrapSuite {
    RsaOaepSha256 = 1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WrappedDek {
    pub suite: WrapSuite,
    pub recipient_key_id: String,
    pub wrapped_dek: Vec<u8>,
}

pub struct EnvelopeMetadata {
    pub file_uuid: [u8; 16],
    pub file_key_id: String,
    pub nonce_prefix: [u8; 4],
    pub plaintext_bytes: u64,
    pub chunk_count: u64,
    pub wraps: Vec<WrappedDek>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvelopeError {
    InvalidMetadata,
    HeaderTooLarge,
    AllocationFailed,
    ChunkOutOfOrder,
    ChunkLengthMismatch,
    IncompleteFile,
    LengthOverflow,
    WriteFailed,
    ReadFailed,
    MalformedHeader,
    MalformedChunk,
    MalformedFooter,
    DigestMismatch,
    TrailingData,
    Crypto(VaultCryptoError),
}

impl From<VaultCryptoError> for EnvelopeError {
    fn from(value: VaultCryptoError) -> Self {
        Self::Crypto(value)
    }
}

pub fn expected_chunk_count(plaintext_bytes: u64) -> u64 {
    if plaintext_bytes == 0 {
        0
    } else {
        ((plaintext_bytes - 1) / SQVE_CHUNK_BYTES as u64) + 1
    }
}

pub struct VaultEnvelopeWriter<W: Write> {
    writer: W,
    key: VaultFileKey,
    metadata: EnvelopeMetadata,
    fixed_header: [u8; SQVE_HEADER_BYTES],
    header_bytes: Vec<u8>,
    stream_hash: Sha256,
    next_chunk_index: u64,
    written_plaintext_bytes: u64,
}

impl<W: Write> VaultEnvelopeWriter<W> {
    pub fn new(
        mut writer: W,
        metadata: EnvelopeMetadata,
        key: VaultFileKey,
    ) -> Result<Self, EnvelopeError> {
        validate_metadata(&metadata)?;
        let header_bytes = serialize_header(&metadata)?;
        let mut stream_hash = Sha256::new();
        stream_hash.update(&header_bytes);
        writer
            .write_all(&header_bytes)
            .map_err(|_| EnvelopeError::WriteFailed)?;
        let mut fixed_header = [0u8; SQVE_HEADER_BYTES];
        fixed_header.copy_from_slice(&header_bytes[..SQVE_HEADER_BYTES]);

        Ok(Self {
            writer,
            key,
            metadata,
            fixed_header,
            header_bytes,
            stream_hash,
            next_chunk_index: 0,
            written_plaintext_bytes: 0,
        })
    }

    /// Accepts exactly the next complete plaintext chunk and encrypts it in place.
    /// The caller must supply a disposable derived buffer, never the evidence WAV buffer.
    pub fn write_chunk(&mut self, plaintext_buffer: &mut [u8]) -> Result<(), EnvelopeError> {
        if self.next_chunk_index >= self.metadata.chunk_count {
            return Err(EnvelopeError::ChunkOutOfOrder);
        }
        let offset = self
            .next_chunk_index
            .checked_mul(SQVE_CHUNK_BYTES as u64)
            .ok_or(EnvelopeError::LengthOverflow)?;
        let remaining = self
            .metadata
            .plaintext_bytes
            .checked_sub(offset)
            .ok_or(EnvelopeError::LengthOverflow)?;
        let expected = remaining.min(SQVE_CHUNK_BYTES as u64) as usize;
        if plaintext_buffer.len() != expected {
            return Err(EnvelopeError::ChunkLengthMismatch);
        }

        let final_chunk = self.next_chunk_index + 1 == self.metadata.chunk_count;
        let (aad, aad_len) = make_chunk_aad(
            &self.fixed_header,
            &self.metadata.file_key_id,
            self.next_chunk_index,
            plaintext_buffer.len() as u32,
            final_chunk,
        )?;
        let nonce = nonce_for_chunk(self.metadata.nonce_prefix, self.next_chunk_index);
        let tag = encrypt_chunk_in_place(&self.key, nonce, &aad[..aad_len], plaintext_buffer)?;

        let ciphertext_len = plaintext_buffer
            .len()
            .checked_add(GCM_TAG_BYTES)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or(EnvelopeError::LengthOverflow)?;
        let mut record_header = [0u8; 16];
        record_header[..8].copy_from_slice(&self.next_chunk_index.to_le_bytes());
        record_header[8..12].copy_from_slice(&(plaintext_buffer.len() as u32).to_le_bytes());
        record_header[12..16].copy_from_slice(&ciphertext_len.to_le_bytes());

        self.writer
            .write_all(&record_header)
            .map_err(|_| EnvelopeError::WriteFailed)?;
        self.writer
            .write_all(plaintext_buffer)
            .map_err(|_| EnvelopeError::WriteFailed)?;
        self.writer
            .write_all(&tag)
            .map_err(|_| EnvelopeError::WriteFailed)?;

        let chunk_plaintext_bytes = plaintext_buffer.len() as u64;
        self.stream_hash.update(record_header);
        self.stream_hash.update(&*plaintext_buffer);
        self.stream_hash.update(tag);
        self.written_plaintext_bytes = self
            .written_plaintext_bytes
            .checked_add(chunk_plaintext_bytes)
            .ok_or(EnvelopeError::LengthOverflow)?;
        self.next_chunk_index += 1;
        Ok(())
    }

    /// Writes the footer only after every declared chunk and byte has been accepted.
    pub fn finish(mut self) -> Result<W, EnvelopeError> {
        if self.next_chunk_index != self.metadata.chunk_count
            || self.written_plaintext_bytes != self.metadata.plaintext_bytes
        {
            return Err(EnvelopeError::IncompleteFile);
        }

        let digest = self.stream_hash.finalize();
        let mut footer = [0u8; SQVE_FOOTER_BYTES];
        footer[..4].copy_from_slice(b"SQVF");
        footer[4..6].copy_from_slice(&1u16.to_le_bytes());
        footer[6..8].copy_from_slice(&(SQVE_FOOTER_BYTES as u16).to_le_bytes());
        footer[8..16].copy_from_slice(&self.metadata.chunk_count.to_le_bytes());
        footer[16..24].copy_from_slice(&self.metadata.plaintext_bytes.to_le_bytes());
        footer[24..56].copy_from_slice(&digest);
        self.writer
            .write_all(&footer)
            .map_err(|_| EnvelopeError::WriteFailed)?;
        Ok(self.writer)
    }

    pub fn serialized_header_bytes(&self) -> &[u8] {
        &self.header_bytes
    }
}

/// Result of a structural SQVE v1 verification. This verifies the serialized
/// stream digest and layout; callers must still authenticate/decrypt every GCM
/// chunk before exposing plaintext.
pub struct EnvelopeVerification {
    pub metadata: EnvelopeMetadata,
    pub serialized_header_bytes: usize,
    pub serialized_file_bytes: u64,
}

/// Verifies an SQVE v1 stream without loading the whole file into memory.
/// At most one maximum-size ciphertext chunk and the bounded header are buffered.
pub fn verify_envelope<R: Read + Seek>(
    reader: &mut R,
) -> Result<EnvelopeVerification, EnvelopeError> {
    let file_len = reader
        .seek(SeekFrom::End(0))
        .map_err(|_| EnvelopeError::ReadFailed)?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|_| EnvelopeError::ReadFailed)?;

    let mut fixed = [0u8; SQVE_HEADER_BYTES];
    reader
        .read_exact(&mut fixed)
        .map_err(|_| EnvelopeError::ReadFailed)?;
    if &fixed[..4] != b"SQVE"
        || u16::from_le_bytes([fixed[4], fixed[5]]) != 1
        || u16::from_le_bytes([fixed[8], fixed[9]]) != 1
        || u16::from_le_bytes([fixed[10], fixed[11]]) != 0
        || u32::from_le_bytes(fixed[12..16].try_into().unwrap()) as usize
            != SQVE_CHUNK_BYTES
        || fixed[56..64].iter().any(|byte| *byte != 0)
    {
        return Err(EnvelopeError::MalformedHeader);
    }

    let header_len = u16::from_le_bytes([fixed[6], fixed[7]]) as usize;
    let key_id_len = u16::from_le_bytes([fixed[52], fixed[53]]) as usize;
    let wrap_count = u16::from_le_bytes([fixed[54], fixed[55]]) as usize;
    if !(SQVE_HEADER_BYTES..=SQVE_MAX_HEADER_BYTES).contains(&header_len)
        || key_id_len == 0
        || key_id_len > SQVE_FILE_KEY_ID_MAX_BYTES
        || wrap_count == 0
    {
        return Err(EnvelopeError::MalformedHeader);
    }

    let mut header = vec![0u8; header_len];
    header[..SQVE_HEADER_BYTES].copy_from_slice(&fixed);
    reader
        .read_exact(&mut header[SQVE_HEADER_BYTES..])
        .map_err(|_| EnvelopeError::ReadFailed)?;

    let file_key_id = std::str::from_utf8(
        header
            .get(SQVE_HEADER_BYTES..SQVE_HEADER_BYTES + key_id_len)
            .ok_or(EnvelopeError::MalformedHeader)?,
    )
    .map_err(|_| EnvelopeError::MalformedHeader)?
    .to_owned();
    if !is_key_id(&file_key_id, SQVE_FILE_KEY_ID_MAX_BYTES) {
        return Err(EnvelopeError::MalformedHeader);
    }

    let mut cursor = SQVE_HEADER_BYTES + key_id_len;
    let mut wraps = Vec::new();
    wraps
        .try_reserve_exact(wrap_count)
        .map_err(|_| EnvelopeError::AllocationFailed)?;
    for _ in 0..wrap_count {
        let record = header.get(cursor..cursor + 8).ok_or(EnvelopeError::MalformedHeader)?;
        let suite_code = u16::from_le_bytes([record[0], record[1]]);
        if suite_code != WrapSuite::RsaOaepSha256 as u16 {
            return Err(EnvelopeError::MalformedHeader);
        }
        let recipient_len = u16::from_le_bytes([record[2], record[3]]) as usize;
        let wrapped_len = u32::from_le_bytes(record[4..8].try_into().unwrap()) as usize;
        cursor += 8;
        if recipient_len == 0 || recipient_len > SQVE_RECIPIENT_ID_MAX_BYTES {
            return Err(EnvelopeError::MalformedHeader);
        }
        let recipient_end = cursor.checked_add(recipient_len).ok_or(EnvelopeError::MalformedHeader)?;
        let wrapped_end = recipient_end.checked_add(wrapped_len).ok_or(EnvelopeError::MalformedHeader)?;
        let recipient = std::str::from_utf8(
            header.get(cursor..recipient_end).ok_or(EnvelopeError::MalformedHeader)?,
        )
        .map_err(|_| EnvelopeError::MalformedHeader)?
        .to_owned();
        if !is_key_id(&recipient, SQVE_RECIPIENT_ID_MAX_BYTES) {
            return Err(EnvelopeError::MalformedHeader);
        }
        let wrapped_dek = header
            .get(recipient_end..wrapped_end)
            .ok_or(EnvelopeError::MalformedHeader)?
            .to_vec();
        wraps.push(WrappedDek {
            suite: WrapSuite::RsaOaepSha256,
            recipient_key_id: recipient,
            wrapped_dek,
        });
        cursor = wrapped_end;
    }
    if cursor != header_len {
        return Err(EnvelopeError::MalformedHeader);
    }

    let plaintext_bytes = u64::from_le_bytes(fixed[16..24].try_into().unwrap());
    let chunk_count = u64::from_le_bytes(fixed[24..32].try_into().unwrap());
    if chunk_count != expected_chunk_count(plaintext_bytes) {
        return Err(EnvelopeError::MalformedHeader);
    }
    let expected_file_len = (header_len as u64)
        .checked_add(plaintext_bytes)
        .and_then(|n| chunk_count.checked_mul(32).and_then(|overhead| n.checked_add(overhead)))
        .and_then(|n| n.checked_add(SQVE_FOOTER_BYTES as u64))
        .ok_or(EnvelopeError::LengthOverflow)?;
    if file_len > expected_file_len {
        return Err(EnvelopeError::TrailingData);
    }
    if file_len != expected_file_len {
        return Err(EnvelopeError::MalformedChunk);
    }

    let metadata = EnvelopeMetadata {
        file_uuid: fixed[32..48].try_into().unwrap(),
        file_key_id,
        nonce_prefix: fixed[48..52].try_into().unwrap(),
        plaintext_bytes,
        chunk_count,
        wraps,
    };
    validate_metadata(&metadata)?;
    let mut stream_hash = Sha256::new();
    stream_hash.update(&header);
    let mut chunk_buffer = vec![0u8; SQVE_CHUNK_BYTES + GCM_TAG_BYTES];

    for index in 0..chunk_count {
        let mut record = [0u8; 16];
        reader
            .read_exact(&mut record)
            .map_err(|_| EnvelopeError::ReadFailed)?;
        let record_index = u64::from_le_bytes(record[..8].try_into().unwrap());
        let plaintext_len = u32::from_le_bytes(record[8..12].try_into().unwrap()) as usize;
        let ciphertext_len = u32::from_le_bytes(record[12..16].try_into().unwrap()) as usize;
        let offset = index
            .checked_mul(SQVE_CHUNK_BYTES as u64)
            .ok_or(EnvelopeError::LengthOverflow)?;
        let expected_plaintext_len = plaintext_bytes
            .checked_sub(offset)
            .ok_or(EnvelopeError::MalformedChunk)?
            .min(SQVE_CHUNK_BYTES as u64) as usize;
        if record_index != index
            || plaintext_len != expected_plaintext_len
            || ciphertext_len != plaintext_len + GCM_TAG_BYTES
            || ciphertext_len > chunk_buffer.len()
        {
            return Err(EnvelopeError::MalformedChunk);
        }
        reader
            .read_exact(&mut chunk_buffer[..ciphertext_len])
            .map_err(|_| EnvelopeError::ReadFailed)?;
        stream_hash.update(record);
        stream_hash.update(&chunk_buffer[..ciphertext_len]);
    }

    let mut footer = [0u8; SQVE_FOOTER_BYTES];
    reader
        .read_exact(&mut footer)
        .map_err(|_| EnvelopeError::ReadFailed)?;
    if &footer[..4] != b"SQVF"
        || u16::from_le_bytes([footer[4], footer[5]]) != 1
        || u16::from_le_bytes([footer[6], footer[7]]) as usize != SQVE_FOOTER_BYTES
        || u64::from_le_bytes(footer[8..16].try_into().unwrap()) != chunk_count
        || u64::from_le_bytes(footer[16..24].try_into().unwrap()) != plaintext_bytes
    {
        return Err(EnvelopeError::MalformedFooter);
    }
    let digest = stream_hash.finalize();
    if digest.as_slice() != &footer[24..56] {
        return Err(EnvelopeError::DigestMismatch);
    }
    if reader
        .read(&mut [0u8; 1])
        .map_err(|_| EnvelopeError::ReadFailed)?
        != 0
    {
        return Err(EnvelopeError::TrailingData);
    }

    Ok(EnvelopeVerification {
        metadata,
        serialized_header_bytes: header_len,
        serialized_file_bytes: file_len,
    })
}

fn validate_metadata(metadata: &EnvelopeMetadata) -> Result<(), EnvelopeError> {
    if !is_key_id(&metadata.file_key_id, SQVE_FILE_KEY_ID_MAX_BYTES)
        || metadata.wraps.is_empty()
        || metadata.chunk_count != expected_chunk_count(metadata.plaintext_bytes)
    {
        return Err(EnvelopeError::InvalidMetadata);
    }
    for (index, wrap) in metadata.wraps.iter().enumerate() {
        if !is_key_id(&wrap.recipient_key_id, SQVE_RECIPIENT_ID_MAX_BYTES)
            || wrap.wrapped_dek.is_empty()
            || wrap.wrapped_dek.len() > u32::MAX as usize
            || metadata.wraps[..index]
                .iter()
                .any(|prior| prior.recipient_key_id == wrap.recipient_key_id)
        {
            return Err(EnvelopeError::InvalidMetadata);
        }
    }
    Ok(())
}

fn serialize_header(metadata: &EnvelopeMetadata) -> Result<Vec<u8>, EnvelopeError> {
    let key_id_len =
        u16::try_from(metadata.file_key_id.len()).map_err(|_| EnvelopeError::HeaderTooLarge)?;
    let wrap_count =
        u16::try_from(metadata.wraps.len()).map_err(|_| EnvelopeError::HeaderTooLarge)?;
    let mut total = SQVE_HEADER_BYTES
        .checked_add(metadata.file_key_id.len())
        .ok_or(EnvelopeError::HeaderTooLarge)?;
    for wrap in &metadata.wraps {
        total = total
            .checked_add(8)
            .and_then(|n| n.checked_add(wrap.recipient_key_id.len()))
            .and_then(|n| n.checked_add(wrap.wrapped_dek.len()))
            .ok_or(EnvelopeError::HeaderTooLarge)?;
    }
    if total > SQVE_MAX_HEADER_BYTES {
        return Err(EnvelopeError::HeaderTooLarge);
    }
    let total_u16 = u16::try_from(total).map_err(|_| EnvelopeError::HeaderTooLarge)?;

    let mut fixed = [0u8; SQVE_HEADER_BYTES];
    fixed[..4].copy_from_slice(b"SQVE");
    fixed[4..6].copy_from_slice(&1u16.to_le_bytes());
    fixed[6..8].copy_from_slice(&total_u16.to_le_bytes());
    fixed[8..10].copy_from_slice(&1u16.to_le_bytes()); // AES-256-GCM chunked v1
    fixed[10..12].copy_from_slice(&0u16.to_le_bytes()); // v1 flags reserved
    fixed[12..16].copy_from_slice(&(SQVE_CHUNK_BYTES as u32).to_le_bytes());
    fixed[16..24].copy_from_slice(&metadata.plaintext_bytes.to_le_bytes());
    fixed[24..32].copy_from_slice(&metadata.chunk_count.to_le_bytes());
    fixed[32..48].copy_from_slice(&metadata.file_uuid);
    fixed[48..52].copy_from_slice(&metadata.nonce_prefix);
    fixed[52..54].copy_from_slice(&key_id_len.to_le_bytes());
    fixed[54..56].copy_from_slice(&wrap_count.to_le_bytes());
    // 56..64 reserved zero.

    let mut header = Vec::<u8>::new();
    header
        .try_reserve_exact(total)
        .map_err(|_| EnvelopeError::AllocationFailed)?;
    header.extend_from_slice(&fixed);
    header.extend_from_slice(metadata.file_key_id.as_bytes());
    for wrap in &metadata.wraps {
        let recipient_len = u16::try_from(wrap.recipient_key_id.len())
            .map_err(|_| EnvelopeError::HeaderTooLarge)?;
        let wrapped_len =
            u32::try_from(wrap.wrapped_dek.len()).map_err(|_| EnvelopeError::HeaderTooLarge)?;
        header.extend_from_slice(&(wrap.suite as u16).to_le_bytes());
        header.extend_from_slice(&recipient_len.to_le_bytes());
        header.extend_from_slice(&wrapped_len.to_le_bytes());
        header.extend_from_slice(wrap.recipient_key_id.as_bytes());
        header.extend_from_slice(&wrap.wrapped_dek);
    }
    debug_assert_eq!(header.len(), total);
    Ok(header)
}

fn make_chunk_aad(
    fixed_header: &[u8; SQVE_HEADER_BYTES],
    file_key_id: &str,
    chunk_index: u64,
    plaintext_len: u32,
    final_chunk: bool,
) -> Result<([u8; 256], usize), EnvelopeError> {
    let id_len = u16::try_from(file_key_id.len()).map_err(|_| EnvelopeError::HeaderTooLarge)?;
    let mut aad = [0u8; 256];
    let mut cursor = 0usize;
    aad[cursor..cursor + AAD_DOMAIN.len()].copy_from_slice(AAD_DOMAIN);
    cursor += AAD_DOMAIN.len();
    aad[cursor..cursor + 52].copy_from_slice(&fixed_header[..52]);
    cursor += 52;
    aad[cursor..cursor + 2].copy_from_slice(&id_len.to_le_bytes());
    cursor += 2;
    aad[cursor..cursor + file_key_id.len()].copy_from_slice(file_key_id.as_bytes());
    cursor += file_key_id.len();
    aad[cursor..cursor + 8].copy_from_slice(&chunk_index.to_le_bytes());
    cursor += 8;
    aad[cursor..cursor + 4].copy_from_slice(&plaintext_len.to_le_bytes());
    cursor += 4;
    let final_flag = if final_chunk { 1u32 } else { 0u32 };
    aad[cursor..cursor + 4].copy_from_slice(&final_flag.to_le_bytes());
    cursor += 4;
    // The caller passes only the populated prefix as AAD (max 207 bytes).
    Ok((aad, cursor))
}

fn is_key_id(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.'
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(plaintext_bytes: u64) -> EnvelopeMetadata {
        EnvelopeMetadata {
            file_uuid: [0x22; 16],
            file_key_id: "file-dek-v1".to_owned(),
            nonce_prefix: [1, 2, 3, 4],
            plaintext_bytes,
            chunk_count: expected_chunk_count(plaintext_bytes),
            wraps: vec![WrappedDek {
                suite: WrapSuite::RsaOaepSha256,
                recipient_key_id: "device-key-v1".to_owned(),
                wrapped_dek: vec![0xAA; 384],
            }],
        }
    }

    #[test]
    fn writes_header_chunk_and_footer_with_exact_lengths() {
        let key = VaultFileKey { bytes: [0x42; 32] };
        let mut writer = VaultEnvelopeWriter::new(Vec::<u8>::new(), metadata(3), key).unwrap();
        let mut chunk = b"abc".to_vec();
        writer.write_chunk(&mut chunk).unwrap();
        let header_len = writer.serialized_header_bytes().len();
        let bytes = writer.finish().unwrap();

        assert_eq!(&bytes[..4], b"SQVE");
        assert_eq!(
            &bytes[header_len + 16 + 3 + 16..header_len + 16 + 3 + 16 + 4],
            b"SQVF"
        );
        assert_eq!(bytes.len(), header_len + 16 + 3 + 16 + SQVE_FOOTER_BYTES);
    }

    #[test]
    fn rejects_wrong_chunk_length_and_incomplete_finish() {
        let key = VaultFileKey { bytes: [0x33; 32] };
        let mut writer = VaultEnvelopeWriter::new(Vec::<u8>::new(), metadata(4), key).unwrap();
        let mut wrong = b"abc".to_vec();
        assert_eq!(
            writer.write_chunk(&mut wrong),
            Err(EnvelopeError::ChunkLengthMismatch)
        );
        assert_eq!(writer.finish().err(), Some(EnvelopeError::IncompleteFile));
    }

    #[test]
    fn empty_file_has_no_chunks_but_has_footer() {
        let key = VaultFileKey { bytes: [0x00; 32] };
        let writer = VaultEnvelopeWriter::new(Vec::<u8>::new(), metadata(0), key).unwrap();
        let header_len = writer.serialized_header_bytes().len();
        let bytes = writer.finish().unwrap();
        assert_eq!(&bytes[header_len..header_len + 4], b"SQVF");
        assert_eq!(bytes.len(), header_len + SQVE_FOOTER_BYTES);
    }
    #[test]
    fn streaming_verifier_round_trips_and_checks_footer_digest() {
        let key = VaultFileKey { bytes: [0x42; 32] };
        let mut writer = VaultEnvelopeWriter::new(Vec::<u8>::new(), metadata(3), key).unwrap();
        let mut chunk = b"abc".to_vec();
        writer.write_chunk(&mut chunk).unwrap();
        let bytes = writer.finish().unwrap();
        let mut cursor = std::io::Cursor::new(bytes.clone());
        let verified = verify_envelope(&mut cursor).unwrap();
        assert_eq!(verified.metadata.plaintext_bytes, 3);
        assert_eq!(verified.metadata.chunk_count, 1);
        assert_eq!(verified.metadata.file_key_id, "file-dek-v1");

        let mut tampered = bytes;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let mut cursor = std::io::Cursor::new(tampered);
        assert!(matches!(
            verify_envelope(&mut cursor),
            Err(EnvelopeError::DigestMismatch)
        ));
    }

    #[test]
    fn streaming_verifier_rejects_trailing_bytes() {
        let key = VaultFileKey { bytes: [0x11; 32] };
        let writer = VaultEnvelopeWriter::new(Vec::<u8>::new(), metadata(0), key).unwrap();
        let mut bytes = writer.finish().unwrap();
        bytes.push(0);
        let mut cursor = std::io::Cursor::new(bytes);
        assert!(matches!(
            verify_envelope(&mut cursor),
            Err(EnvelopeError::TrailingData)
        ));
    }

}
