//! AES-256-GCM chunk primitives for SQRecorder Vault.
//!
//! This crate owns per-file DEK bytes, CSPRNG generation, authenticated chunk
//! operations, and SHA-256. Platform Keystore/CNG adapters perform asymmetric
//! private-key operations and enforce authenticated unwrap.
#![deny(unsafe_op_in_unsafe_fn)]

pub mod envelope;
pub mod v2;

use aes_gcm::{
    Aes256Gcm, Nonce, Tag,
    aead::{AeadInOut, KeyInit},
};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub const DEK_BYTES: usize = 32;
pub const GCM_NONCE_BYTES: usize = 12;
pub const GCM_TAG_BYTES: usize = 16;
pub const NONCE_PREFIX_BYTES: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultCryptoError {
    RandomSourceUnavailable,
    InvalidKeyLength,
    InvalidNonceLength,
    InvalidTagLength,
    EncryptionFailed,
    AuthenticationFailed,
}

/// Non-cloneable per-file DEK; memory is zeroized when the key is dropped.
pub struct VaultFileKey {
    bytes: [u8; DEK_BYTES],
}

impl VaultFileKey {
    /// Import a DEK produced by an authenticated platform unwrap. The caller
    /// retains responsibility for zeroizing its input buffer after this copy.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VaultCryptoError> {
        if bytes.len() != DEK_BYTES {
            return Err(VaultCryptoError::InvalidKeyLength);
        }
        let mut key = [0u8; DEK_BYTES];
        key.copy_from_slice(bytes);
        Ok(Self { bytes: key })
    }

    /// Transient copy used only for platform public-key wrapping. Zeroize it
    /// immediately after the platform operation; never persist or log it.
    pub fn copy_for_public_wrap(&self) -> [u8; DEK_BYTES] {
        self.bytes
    }

    pub fn generate() -> Result<Self, VaultCryptoError> {
        let mut bytes = [0u8; DEK_BYTES];
        if getrandom::fill(&mut bytes).is_err() {
            bytes.zeroize();
            return Err(VaultCryptoError::RandomSourceUnavailable);
        }
        Ok(Self { bytes })
    }
}

impl Drop for VaultFileKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Generate the random 32-bit prefix used with the per-file chunk counter.
pub fn random_nonce_prefix() -> Result<[u8; NONCE_PREFIX_BYTES], VaultCryptoError> {
    let mut prefix = [0u8; NONCE_PREFIX_BYTES];
    if getrandom::fill(&mut prefix).is_err() {
        prefix.zeroize();
        return Err(VaultCryptoError::RandomSourceUnavailable);
    }
    Ok(prefix)
}

/// SQVE v1 nonce: random file prefix followed by the chunk index in big-endian.
pub fn nonce_for_chunk(
    prefix: [u8; NONCE_PREFIX_BYTES],
    chunk_index: u64,
) -> [u8; GCM_NONCE_BYTES] {
    let mut nonce = [0u8; GCM_NONCE_BYTES];
    nonce[..NONCE_PREFIX_BYTES].copy_from_slice(&prefix);
    nonce[NONCE_PREFIX_BYTES..].copy_from_slice(&chunk_index.to_be_bytes());
    nonce
}

/// Encrypts the supplied chunk buffer in place. The 16-byte tag is returned
/// separately for the envelope writer. No heap allocation occurs here.
pub fn encrypt_chunk_in_place(
    key: &VaultFileKey,
    nonce: [u8; GCM_NONCE_BYTES],
    associated_data: &[u8],
    plaintext_buffer: &mut [u8],
) -> Result<[u8; GCM_TAG_BYTES], VaultCryptoError> {
    let cipher =
        Aes256Gcm::new_from_slice(&key.bytes).map_err(|_| VaultCryptoError::InvalidKeyLength)?;
    let nonce =
        Nonce::try_from(nonce.as_slice()).map_err(|_| VaultCryptoError::InvalidNonceLength)?;
    let tag = cipher
        .encrypt_inout_detached(&nonce, associated_data, (&mut *plaintext_buffer).into())
        .map_err(|_| VaultCryptoError::EncryptionFailed)?;
    let mut tag_bytes = [0u8; GCM_TAG_BYTES];
    tag_bytes.copy_from_slice(tag.as_ref());
    Ok(tag_bytes)
}

/// Decrypts in place only after AEAD verification. On authentication failure,
/// the supplied buffer is zeroized and no plaintext is returned.
pub fn decrypt_chunk_in_place(
    key: &VaultFileKey,
    nonce: [u8; GCM_NONCE_BYTES],
    associated_data: &[u8],
    ciphertext_buffer: &mut [u8],
    tag_bytes: &[u8],
) -> Result<(), VaultCryptoError> {
    if tag_bytes.len() != GCM_TAG_BYTES {
        ciphertext_buffer.zeroize();
        return Err(VaultCryptoError::InvalidTagLength);
    }
    let cipher =
        Aes256Gcm::new_from_slice(&key.bytes).map_err(|_| VaultCryptoError::InvalidKeyLength)?;
    let nonce =
        Nonce::try_from(nonce.as_slice()).map_err(|_| VaultCryptoError::InvalidNonceLength)?;
    let tag = Tag::try_from(tag_bytes).map_err(|_| VaultCryptoError::InvalidTagLength)?;
    if cipher
        .decrypt_inout_detached(
            &nonce,
            associated_data,
            (&mut *ciphertext_buffer).into(),
            &tag,
        )
        .is_err()
    {
        ciphertext_buffer.zeroize();
        return Err(VaultCryptoError::AuthenticationFailed);
    }
    Ok(())
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_256_gcm_matches_nist_empty_message_vector() {
        let key = VaultFileKey {
            bytes: [0u8; DEK_BYTES],
        };
        let nonce = [0u8; GCM_NONCE_BYTES];
        let mut empty = [];
        let tag = encrypt_chunk_in_place(&key, nonce, &[], &mut empty).unwrap();
        assert_eq!(
            tag,
            [
                0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb,
                0x73, 0x8b,
            ],
        );
    }

    #[test]
    fn chunk_round_trip_binds_associated_data() {
        let key = VaultFileKey {
            bytes: [0x42u8; DEK_BYTES],
        };
        let nonce = nonce_for_chunk([1, 2, 3, 4], 9);
        let aad = b"file-id|chunk-index=9|len=5";
        let original = b"SQREC";
        let mut buffer = original.to_vec();
        let tag = encrypt_chunk_in_place(&key, nonce, aad, &mut buffer).unwrap();
        assert_ne!(buffer.as_slice(), original.as_slice());
        decrypt_chunk_in_place(&key, nonce, aad, &mut buffer, &tag).unwrap();
        assert_eq!(buffer.as_slice(), original.as_slice());
    }

    #[test]
    fn authentication_failure_zeroizes_buffer() {
        let key = VaultFileKey {
            bytes: [0x11u8; DEK_BYTES],
        };
        let nonce = nonce_for_chunk([5, 6, 7, 8], 0);
        let mut buffer = b"tamper".to_vec();
        let tag = encrypt_chunk_in_place(&key, nonce, b"aad", &mut buffer).unwrap();
        let mut wrong_tag = tag;
        wrong_tag[0] ^= 1;
        assert_eq!(
            decrypt_chunk_in_place(&key, nonce, b"aad", &mut buffer, &wrong_tag),
            Err(VaultCryptoError::AuthenticationFailed),
        );
        assert!(buffer.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            sha256(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ],
        );
    }
}

/// SQVE v2 header-authentication primitive. The DEK never leaves this crate;
/// HKDF domain separation and HMAC are implemented here over the pinned SHA-256.
pub(crate) fn sqve_v2_header_mac(
    key: &VaultFileKey,
    salt: &[u8; 32],
    authenticated_bytes: &[u8],
) -> [u8; 32] {
    let mut prk = hmac_sha256(salt, &key.bytes);
    let info = b"SQREC-SQVE2-HEADER-MAC-v1";
    let mut expand_input = Vec::with_capacity(info.len() + 1);
    expand_input.extend_from_slice(info);
    expand_input.push(1);
    let header_key = hmac_sha256(&prk, &expand_input);
    hmac_sha256(&header_key, authenticated_bytes)
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut normalized = [0u8; BLOCK];
    if key.len() > BLOCK {
        normalized[..32].copy_from_slice(&sha256(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; BLOCK];
    let mut outer_pad = [0x5cu8; BLOCK];
    for index in 0..BLOCK {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    let digest = outer.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    normalized.zeroize();
    inner_pad.zeroize();
    outer_pad.zeroize();
    output
}
