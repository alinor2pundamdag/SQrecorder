//! SQVE v2 canonical wire primitives and authenticated streaming writer.
//! V1 serialization remains isolated in `envelope`; this module never dispatches
//! V2 input through a V1 parser or writer.
use std::io::{Read, Seek, SeekFrom, Write};

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::{
    GCM_TAG_BYTES, VaultCryptoError, VaultFileKey, decrypt_chunk_in_place,
    encrypt_chunk_in_place, nonce_for_chunk, sqve_v2_header_mac,
};

pub const VERSION: u16 = 2;
pub const CONTENT_SUITE_AES_256_GCM: u16 = 0x0001;
pub const WRAP_SUITE_RSA_OAEP_SHA256_MGF1_SHA256_EMPTY: u16 = 0x0001;
pub const WRAP_SUITE_ECDH_P256_HKDF_SHA256_AES_GCM: u16 = 0x0002;
pub const CHUNK_BYTES: usize = 1_048_576;
pub const HEADER_MAX_BYTES: usize = 65_535;
pub const RECIPIENTS_MAX: usize = 16;
pub const WRAPPED_MAX_BYTES: usize = 8_192;
const FIXED_HEADER_BYTES: usize = 90;
const HEADER_MAC_BYTES: usize = 32;
const FOOTER_BYTES: usize = 56;
const CHUNK_AAD_DOMAIN: &[u8] = b"SQREC-SQVE2-CHUNK-AAD-v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipientWrap {
    pub suite: u16,
    pub key_id: String,
    pub wrapped: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Header {
    pub file_id: [u8; 16],
    pub file_salt: [u8; 32],
    pub nonce_prefix: [u8; 4],
    pub plaintext_len: u64,
    pub chunk_count: u64,
    pub recipients: Vec<RecipientWrap>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidHeader,
    InvalidRecipient,
    UnsupportedSuite,
    Allocation,
    LengthOverflow,
    InputLength,
    Read,
    Write,
    ChunkOrder,
    ChunkLength,
    Incomplete,
    Authentication,
    MalformedChunk,
    MalformedFooter,
    DigestMismatch,
    TrailingData,
    Crypto(VaultCryptoError),
}
impl From<VaultCryptoError> for Error {
    fn from(value: VaultCryptoError) -> Self { Self::Crypto(value) }
}

pub fn expected_chunks(len: u64) -> u64 {
    if len == 0 { 0 } else { (len - 1) / CHUNK_BYTES as u64 + 1 }
}

fn valid_key_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.bytes().all(|b|
        b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
}

fn validate(header: &Header) -> Result<(), Error> {
    if header.chunk_count != expected_chunks(header.plaintext_len)
        || header.recipients.is_empty() || header.recipients.len() > RECIPIENTS_MAX {
        return Err(Error::InvalidHeader);
    }
    let mut prior: Option<&str> = None;
    for item in &header.recipients {
        if !valid_key_id(&item.key_id) || item.wrapped.is_empty()
            || item.wrapped.len() > WRAPPED_MAX_BYTES {
            return Err(Error::InvalidRecipient);
        }
        if prior.is_some_and(|p| p.as_bytes() >= item.key_id.as_bytes()) {
            return Err(Error::InvalidRecipient);
        }
        if item.suite != WRAP_SUITE_RSA_OAEP_SHA256_MGF1_SHA256_EMPTY
            && item.suite != WRAP_SUITE_ECDH_P256_HKDF_SHA256_AES_GCM {
            return Err(Error::UnsupportedSuite);
        }
        prior = Some(&item.key_id);
    }
    Ok(())
}

/// Serialize the canonical header and append its DEK-derived HMAC. Recipient
/// ordering is required canonical input; this function rejects, never sorts.
pub fn serialize_header(header: &Header, key: &VaultFileKey) -> Result<Vec<u8>, Error> {
    validate(header)?;
    let mut body = Vec::new();
    body.try_reserve_exact(FIXED_HEADER_BYTES).map_err(|_| Error::Allocation)?;
    body.extend_from_slice(b"SQVE");
    body.extend_from_slice(&VERSION.to_be_bytes());
    body.extend_from_slice(&0u32.to_be_bytes()); // patched total header length
    body.extend_from_slice(&CONTENT_SUITE_AES_256_GCM.to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes()); // flags
    body.extend_from_slice(&header.file_id);
    body.extend_from_slice(&header.file_salt);
    body.extend_from_slice(&header.nonce_prefix);
    body.extend_from_slice(&(CHUNK_BYTES as u32).to_be_bytes());
    body.extend_from_slice(&header.plaintext_len.to_be_bytes());
    body.extend_from_slice(&header.chunk_count.to_be_bytes());
    body.extend_from_slice(&(header.recipients.len() as u16).to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes()); // reserved
    debug_assert_eq!(body.len(), FIXED_HEADER_BYTES);
    for r in &header.recipients {
        let id_len = u16::try_from(r.key_id.len()).map_err(|_| Error::InvalidRecipient)?;
        let wrapped_len = u32::try_from(r.wrapped.len()).map_err(|_| Error::LengthOverflow)?;
        body.extend_from_slice(&r.suite.to_be_bytes());
        body.extend_from_slice(&id_len.to_be_bytes());
        body.extend_from_slice(&wrapped_len.to_be_bytes());
        body.extend_from_slice(r.key_id.as_bytes());
        body.extend_from_slice(&r.wrapped);
    }
    let total = body.len().checked_add(HEADER_MAC_BYTES).ok_or(Error::LengthOverflow)?;
    if total > HEADER_MAX_BYTES { return Err(Error::InvalidHeader); }
    body[6..10].copy_from_slice(&(total as u32).to_be_bytes());
    let mac = sqve_v2_header_mac(key, &header.file_salt, &body);
    body.extend_from_slice(&mac);
    Ok(body)
}

/// Parse bounded canonical bytes and authenticate the header before returning
/// any metadata to a caller. The supplied DEK must already be authenticated by
/// its platform unwrap operation.
pub fn parse_header(bytes: &[u8], key: &VaultFileKey) -> Result<Header, Error> {
    if bytes.len() < FIXED_HEADER_BYTES + HEADER_MAC_BYTES || bytes.len() > HEADER_MAX_BYTES
        || &bytes[..4] != b"SQVE" || u16::from_be_bytes(bytes[4..6].try_into().unwrap()) != VERSION
        || u32::from_be_bytes(bytes[6..10].try_into().unwrap()) as usize != bytes.len()
        || u16::from_be_bytes(bytes[10..12].try_into().unwrap()) != CONTENT_SUITE_AES_256_GCM
        || bytes[12..14] != [0, 0]
        || u32::from_be_bytes(bytes[66..70].try_into().unwrap()) as usize != CHUNK_BYTES
         {
        return Err(Error::InvalidHeader);
    }
    let mac_at = bytes.len() - HEADER_MAC_BYTES;
    let salt: [u8; 32] = bytes[30..62]
        .ok_or(Error::InvalidHeader)?.try_into().map_err(|_| Error::InvalidHeader)?;
    let expected = sqve_v2_header_mac(key, &salt, &bytes[..mac_at]);
    if !constant_time_eq(&expected, &bytes[mac_at..]) { return Err(Error::Authentication); }

    let plaintext_len = u64::from_be_bytes(bytes[70..78].try_into().unwrap());
    let chunk_count = u64::from_be_bytes(bytes[78..86].try_into().unwrap());
    let count = u16::from_be_bytes(bytes[86..88].try_into().unwrap()) as usize;
    if bytes[88..90] != [0, 0] || count == 0 || count > RECIPIENTS_MAX {
        return Err(Error::InvalidHeader);
    }
    let mut cursor = FIXED_HEADER_BYTES;
    let mut recipients = Vec::new();
    recipients.try_reserve_exact(count).map_err(|_| Error::Allocation)?;
    for _ in 0..count {
        let fixed = bytes.get(cursor..cursor.checked_add(8).ok_or(Error::LengthOverflow)?)
            .filter(|r| r.len() == 8).ok_or(Error::InvalidHeader)?;
        let suite = u16::from_be_bytes(fixed[0..2].try_into().unwrap());
        let id_len = u16::from_be_bytes(fixed[2..4].try_into().unwrap()) as usize;
        let wrapped_len = u32::from_be_bytes(fixed[4..8].try_into().unwrap()) as usize;
        cursor += 8;
        let id_end = cursor.checked_add(id_len).ok_or(Error::LengthOverflow)?;
        let wrap_end = id_end.checked_add(wrapped_len).ok_or(Error::LengthOverflow)?;
        if wrap_end > mac_at { return Err(Error::InvalidHeader); }
        let key_id = std::str::from_utf8(&bytes[cursor..id_end]).map_err(|_| Error::InvalidRecipient)?.to_owned();
        let wrapped = bytes[id_end..wrap_end].to_vec();
        recipients.push(RecipientWrap { suite, key_id, wrapped });
        cursor = wrap_end;
    }
    if cursor != mac_at { return Err(Error::InvalidHeader); }
    let header = Header {
        file_id: bytes[14..30].try_into().unwrap(),
        file_salt: salt,
        nonce_prefix: bytes[62..66].try_into().unwrap(),
        plaintext_len,
        chunk_count,
        recipients,
    };
    validate(&header)?;
    Ok(header)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn chunk_nonce(prefix: [u8; 4], index: u64) -> [u8; 12] {
    nonce_for_chunk(prefix, index)
}

pub fn chunk_aad(header: &Header, index: u64, plaintext_len: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(84 + CHUNK_AAD_DOMAIN.len());
    aad.extend_from_slice(CHUNK_AAD_DOMAIN);
    aad.extend_from_slice(&VERSION.to_be_bytes());
    aad.extend_from_slice(&CONTENT_SUITE_AES_256_GCM.to_be_bytes());
    aad.extend_from_slice(&header.file_id);
    aad.extend_from_slice(&header.file_salt);
    aad.extend_from_slice(&header.nonce_prefix);
    aad.extend_from_slice(&(CHUNK_BYTES as u32).to_be_bytes());
    aad.extend_from_slice(&header.plaintext_len.to_be_bytes());
    aad.extend_from_slice(&index.to_be_bytes());
    aad.extend_from_slice(&plaintext_len.to_be_bytes());
    aad
}

/// Authenticated chunk decrypt API. Failed tags are zeroized by the core GCM
/// primitive; callers must not write or publish the buffer on error.
pub fn decrypt_chunk(
    key: &VaultFileKey, header: &Header, index: u64, plaintext_len: u32,
    ciphertext: &mut [u8], tag: &[u8],
) -> Result<(), Error> {
    if index >= header.chunk_count || header.chunk_count != expected_chunks(header.plaintext_len) {
        return Err(Error::MalformedChunk);
    }
    let offset = index.checked_mul(CHUNK_BYTES as u64).ok_or(Error::LengthOverflow)?;
    let expected = header.plaintext_len.checked_sub(offset).ok_or(Error::MalformedChunk)?
        .min(CHUNK_BYTES as u64) as usize;
    if ciphertext.len() != expected || plaintext_len as usize != expected || expected == 0 {
        return Err(Error::MalformedChunk);
    }
    decrypt_chunk_in_place(key, chunk_nonce(header.nonce_prefix, index),
        &chunk_aad(header, index, plaintext_len), ciphertext, tag)?;
    Ok(())
}

pub struct Writer<W: Write> {
    output: W,
    key: VaultFileKey,
    header: Header,
    hash: Sha256,
    next: u64,
    written: u64,
}
impl<W: Write> Writer<W> {
    pub fn new(mut output: W, header: Header, key: VaultFileKey) -> Result<Self, Error> {
        let encoded = serialize_header(&header, &key)?;
        output.write_all(&encoded).map_err(|_| Error::Write)?;
        let mut hash = Sha256::new();
        hash.update(&encoded);
        Ok(Self { output, key, header, hash, next: 0, written: 0 })
    }
    pub fn write_chunk(&mut self, plaintext: &mut [u8]) -> Result<(), Error> {
        if self.next >= self.header.chunk_count { return Err(Error::ChunkOrder); }
        let offset = self.next.checked_mul(CHUNK_BYTES as u64).ok_or(Error::LengthOverflow)?;
        let expected = self.header.plaintext_len.checked_sub(offset).ok_or(Error::ChunkLength)?
            .min(CHUNK_BYTES as u64) as usize;
        if plaintext.len() != expected || expected == 0 { return Err(Error::ChunkLength); }
        let index = self.next;
        let aad = chunk_aad(&self.header, index, expected as u32);
        let nonce = chunk_nonce(self.header.nonce_prefix, index);
        let tag = encrypt_chunk_in_place(&self.key, nonce, &aad, plaintext)?;
        let ciphertext_len = u32::try_from(expected + GCM_TAG_BYTES).map_err(|_| Error::LengthOverflow)?;
        let mut record = [0u8; 16];
        record[..8].copy_from_slice(&index.to_be_bytes());
        record[8..12].copy_from_slice(&(expected as u32).to_be_bytes());
        record[12..16].copy_from_slice(&ciphertext_len.to_be_bytes());
        self.output.write_all(&record).map_err(|_| Error::Write)?;
        self.output.write_all(plaintext).map_err(|_| Error::Write)?;
        self.output.write_all(&tag).map_err(|_| Error::Write)?;
        self.hash.update(record);
        self.hash.update(&*plaintext);
        self.hash.update(tag);
        self.written = self.written.checked_add(expected as u64).ok_or(Error::LengthOverflow)?;
        self.next += 1;
        Ok(())
    }
    pub fn finish(mut self) -> Result<W, Error> {
        if self.next != self.header.chunk_count || self.written != self.header.plaintext_len {
            return Err(Error::Incomplete);
        }
        let digest = self.hash.finalize();
        let mut footer = [0u8; FOOTER_BYTES];
        footer[..4].copy_from_slice(b"SQVF");
        footer[4..6].copy_from_slice(&VERSION.to_be_bytes());
        footer[6..8].copy_from_slice(&(FOOTER_BYTES as u16).to_be_bytes());
        footer[8..16].copy_from_slice(&self.header.chunk_count.to_be_bytes());
        footer[16..24].copy_from_slice(&self.header.plaintext_len.to_be_bytes());
        footer[24..56].copy_from_slice(&digest);
        self.output.write_all(&footer).map_err(|_| Error::Write)?;
        Ok(self.output)
    }
}


/// Reads and authenticates a complete V2 envelope, including every chunk tag,
/// footer digest, exact file length and EOF. Plaintext is zeroized per chunk
/// and never returned by this verifier.
pub fn verify_authenticated_stream<R: Read + Seek>(
    input: &mut R, key: &VaultFileKey,
) -> Result<Header, Error> {
    let file_len = input.seek(SeekFrom::End(0)).map_err(|_| Error::Read)?;
    input.seek(SeekFrom::Start(0)).map_err(|_| Error::Read)?;
    let mut fixed = [0u8; FIXED_HEADER_BYTES];
    input.read_exact(&mut fixed).map_err(|_| Error::Read)?;
    if &fixed[..4] != b"SQVE" || u16::from_be_bytes(fixed[4..6].try_into().unwrap()) != VERSION {
        return Err(Error::InvalidHeader);
    }
    let header_len = u32::from_be_bytes(fixed[6..10].try_into().unwrap()) as usize;
    if !(FIXED_HEADER_BYTES + HEADER_MAC_BYTES..=HEADER_MAX_BYTES).contains(&header_len) {
        return Err(Error::InvalidHeader);
    }
    let mut header_bytes = Vec::new();
    header_bytes.try_reserve_exact(header_len).map_err(|_| Error::Allocation)?;
    header_bytes.extend_from_slice(&fixed);
    header_bytes.resize(header_len, 0);
    input.read_exact(&mut header_bytes[FIXED_HEADER_BYTES..]).map_err(|_| Error::Read)?;
    let header = parse_header(&header_bytes, key)?;
    let expected_len = (header_len as u64)
        .checked_add(header.plaintext_len)
        .and_then(|n| header.chunk_count.checked_mul(32).and_then(|o| n.checked_add(o)))
        .and_then(|n| n.checked_add(FOOTER_BYTES as u64)).ok_or(Error::LengthOverflow)?;
    if file_len != expected_len { return Err(if file_len > expected_len { Error::TrailingData } else { Error::MalformedChunk }); }

    let mut hash = Sha256::new();
    hash.update(&header_bytes);
    let mut ciphertext = Vec::new();
    ciphertext.try_reserve_exact(CHUNK_BYTES).map_err(|_| Error::Allocation)?;
    ciphertext.resize(CHUNK_BYTES, 0);
    for index in 0..header.chunk_count {
        let mut record = [0u8; 16];
        input.read_exact(&mut record).map_err(|_| Error::Read)?;
        let got_index = u64::from_be_bytes(record[..8].try_into().unwrap());
        let plain_len = u32::from_be_bytes(record[8..12].try_into().unwrap()) as usize;
        let cipher_len = u32::from_be_bytes(record[12..16].try_into().unwrap()) as usize;
        let offset = index.checked_mul(CHUNK_BYTES as u64).ok_or(Error::LengthOverflow)?;
        let expected_plain = header.plaintext_len.checked_sub(offset).ok_or(Error::MalformedChunk)?
            .min(CHUNK_BYTES as u64) as usize;
        if got_index != index || plain_len != expected_plain || cipher_len != plain_len + GCM_TAG_BYTES {
            return Err(Error::MalformedChunk);
        }
        input.read_exact(&mut ciphertext[..plain_len]).map_err(|_| Error::Read)?;
        let mut tag = [0u8; GCM_TAG_BYTES];
        input.read_exact(&mut tag).map_err(|_| Error::Read)?;
        hash.update(record);
        hash.update(&ciphertext[..plain_len]);
        hash.update(tag);
        decrypt_chunk(key, &header, index, plain_len as u32, &mut ciphertext[..plain_len], &tag)?;
        ciphertext[..plain_len].zeroize();
        tag.zeroize();
    }
    let mut footer = [0u8; FOOTER_BYTES];
    input.read_exact(&mut footer).map_err(|_| Error::Read)?;
    if &footer[..4] != b"SQVF" || u16::from_be_bytes(footer[4..6].try_into().unwrap()) != VERSION
        || u16::from_be_bytes(footer[6..8].try_into().unwrap()) as usize != FOOTER_BYTES
        || u64::from_be_bytes(footer[8..16].try_into().unwrap()) != header.chunk_count
        || u64::from_be_bytes(footer[16..24].try_into().unwrap()) != header.plaintext_len {
        return Err(Error::MalformedFooter);
    }
    let digest = hash.finalize();
    if !constant_time_eq(&digest, &footer[24..56]) { return Err(Error::DigestMismatch); }
    if input.read(&mut [0u8; 1]).map_err(|_| Error::Read)? != 0 { return Err(Error::TrailingData); }
    Ok(header)
}

/// Fixed-length input stream encryption with a single reusable 1 MiB buffer.
/// It never accepts short input or silently ignores trailing bytes.
pub fn encrypt_stream<R: Read, W: Write>(
    input: &mut R, output: W, header: Header, key: VaultFileKey,
) -> Result<W, Error> {
    let len = header.plaintext_len;
    let count = header.chunk_count;
    let mut writer = Writer::new(output, header, key)?;
    let mut buf = Vec::new();
    buf.try_reserve_exact(CHUNK_BYTES).map_err(|_| Error::Allocation)?;
    buf.resize(CHUNK_BYTES, 0);
    for i in 0..count {
        let size = (len - i * CHUNK_BYTES as u64).min(CHUNK_BYTES as u64) as usize;
        input.read_exact(&mut buf[..size]).map_err(|e|
            if e.kind() == std::io::ErrorKind::UnexpectedEof { Error::InputLength } else { Error::Read })?;
        let result = writer.write_chunk(&mut buf[..size]);
        buf[..size].zeroize();
        result?;
    }
    let mut trailing = [0u8; 1];
    if input.read(&mut trailing).map_err(|_| Error::Read)? != 0 {
        trailing.zeroize();
        return Err(Error::InputLength);
    }
    trailing.zeroize();
    writer.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Header {
        Header { file_id: [0x11;16], file_salt: [0x22;32], nonce_prefix:[1,2,3,4],
            plaintext_len: 3, chunk_count: 1, recipients: vec![RecipientWrap {
                suite: WRAP_SUITE_ECDH_P256_HKDF_SHA256_AES_GCM, key_id:"device:primary".into(),
                wrapped: vec![0x77; 64] }] }
    }
    #[test]
    fn v2_header_round_trips_and_authenticates() {
        let key = VaultFileKey::from_bytes(&[0x42;32]).unwrap();
        let bytes = serialize_header(&sample(), &key).unwrap();
        let parsed = parse_header(&bytes, &key).unwrap();
        assert_eq!(parsed, sample());
        let mut changed = bytes;
        changed[20] ^= 1;
        assert_eq!(parse_header(&changed, &key), Err(Error::Authentication));
    }
    #[test]
    fn v2_rejects_noncanonical_recipient_order_and_trailing_header_bytes() {
        let key = VaultFileKey::from_bytes(&[0x42;32]).unwrap();
        let mut h = sample();
        h.recipients.push(RecipientWrap { suite: 2, key_id:"aaa".into(), wrapped:vec![1] });
        assert_eq!(serialize_header(&h, &key), Err(Error::InvalidRecipient));
        let bytes = serialize_header(&sample(), &key).unwrap();
        let mut extra = bytes.clone();
        extra.push(0);
        assert_eq!(parse_header(&extra, &key), Err(Error::InvalidHeader));
    }
    #[test]
    fn v2_chunk_round_trip_and_aad_binding() {
        let key = VaultFileKey::from_bytes(&[0x31;32]).unwrap();
        let h = sample();
        let mut data = b"abc".to_vec();
        let tag = encrypt_chunk_in_place(&key, chunk_nonce(h.nonce_prefix,0),
            &chunk_aad(&h,0,3), &mut data).unwrap();
        decrypt_chunk(&key,&h,0,3,&mut data,&tag).unwrap();
        assert_eq!(&data,b"abc");
        let mut bad = data.clone();
        assert_ne!(chunk_aad(&h,0,3), chunk_aad(&h,1,3));
        assert_eq!(decrypt_chunk(&key,&h,1,3,&mut bad,&tag),Err(Error::MalformedChunk));
    }

    #[test]
    fn hmac_sha256_matches_rfc_4231_case_1() {
        let key = [0x0bu8; 20];
        let digest = crate::hmac_sha256(&key, b"Hi There");
        assert_eq!(digest, [
            0xf7,0xbc,0x83,0xf4,0x30,0x53,0x84,0x24,0xb1,0x32,0x98,0xe6,0xaa,0x6f,0xb1,0x43,
            0xef,0x4d,0x59,0xa1,0x49,0x46,0x17,0x59,0x97,0x47,0x9d,0xbc,0x2d,0x1a,0x3c,0xd8
        ]);
    }

    #[test]
    fn v2_stream_writer_verifier_round_trip() {
        let key = VaultFileKey::from_bytes(&[0x55;32]).unwrap();
        let mut source = std::io::Cursor::new(b"SQV".to_vec());
        let encoded = encrypt_stream(&mut source, Vec::new(), sample(), key).unwrap();
        let mut file = std::io::Cursor::new(encoded);
        let verify_key = VaultFileKey::from_bytes(&[0x55;32]).unwrap();
        assert_eq!(verify_authenticated_stream(&mut file, &verify_key).unwrap(), sample());
        let mut tampered = file.into_inner();
        let header_len = u32::from_be_bytes(tampered[6..10].try_into().unwrap()) as usize;
        tampered[header_len + 16] ^= 1;
        let mut bad = std::io::Cursor::new(tampered);
        let bad_key = VaultFileKey::from_bytes(&[0x55;32]).unwrap();
        assert!(verify_authenticated_stream(&mut bad, &bad_key).is_err());
    }
}
