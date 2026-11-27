//! AES-GCM file crypto core; platform adapter owns Keystore/auth policy.
#![forbid(unsafe_code)]
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use zeroize::Zeroizing;
pub const DEK_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 12;
pub const MAGIC: &[u8; 4] = b"SQVE";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultError {
    InvalidEnvelope,
    UnsupportedVersion,
    InvalidKey,
    RandomUnavailable,
    AuthenticationFailed,
    WrapFailed,
    UnwrapFailed,
}
/// Production implementation must enforce authentication-bound Android Keystore unwrap.
pub trait DekWrapper {
    fn wrap_dek(&self, dek: &[u8; 32]) -> Result<Vec<u8>, VaultError>;
    fn unwrap_dek(&self, wrapped: &[u8]) -> Result<[u8; 32], VaultError>;
}
pub struct EncryptedFile {
    pub envelope: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
}
pub fn encrypt_file<W: DekWrapper>(
    w: &W,
    plain: &[u8],
    aad: &[u8],
) -> Result<EncryptedFile, VaultError> {
    // The guard zeroizes on every return path, including RNG and adapter errors.
    let mut dek = Zeroizing::new([0u8; DEK_BYTES]);
    getrandom::getrandom(&mut *dek).map_err(|_| VaultError::RandomUnavailable)?;
    let enc = encrypt_dek(&dek, plain, aad);
    let wrap = w.wrap_dek(&dek);
    let (n, c) = enc?;
    let wrapped_dek = wrap?;
    let mut envelope = Vec::with_capacity(17 + c.len());
    envelope.extend_from_slice(MAGIC);
    envelope.push(1);
    envelope.extend_from_slice(&n);
    envelope.extend_from_slice(&c);
    Ok(EncryptedFile {
        envelope,
        wrapped_dek,
    })
}
fn encrypt_dek(k: &[u8; 32], p: &[u8], a: &[u8]) -> Result<([u8; 12], Vec<u8>), VaultError> {
    let c = Aes256Gcm::new_from_slice(k).map_err(|_| VaultError::InvalidKey)?;
    let mut n = [0; 12];
    getrandom::getrandom(&mut n).map_err(|_| VaultError::RandomUnavailable)?;
    let x = c
        .encrypt(Nonce::from_slice(&n), Payload { msg: p, aad: a })
        .map_err(|_| VaultError::AuthenticationFailed)?;
    Ok((n, x))
}
pub fn decrypt_file<W: DekWrapper>(
    w: &W,
    e: &[u8],
    wrapped: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, VaultError> {
    if e.len() < 33 || &e[..4] != MAGIC {
        return Err(VaultError::InvalidEnvelope);
    }
    if e[4] != 1 {
        return Err(VaultError::UnsupportedVersion);
    }
    // Wrapped-key adapters may return an error; successful plaintext key material
    // is guarded so all subsequent errors still trigger zeroization.
    let k = Zeroizing::new(w.unwrap_dek(wrapped)?);
    let c = Aes256Gcm::new_from_slice(&k[..]).map_err(|_| VaultError::InvalidKey)?;
    c.decrypt(Nonce::from_slice(&e[5..17]), Payload { msg: &e[17..], aad })
        .map_err(|_| VaultError::AuthenticationFailed)
}
#[cfg(test)]
mod tests {
    use super::*;
    struct Fake([u8; 32]);
    impl DekWrapper for Fake {
        fn wrap_dek(&self, k: &[u8; 32]) -> Result<Vec<u8>, VaultError> {
            Ok(k.iter().zip(self.0).map(|(a, b)| a ^ b).collect())
        }
        fn unwrap_dek(&self, b: &[u8]) -> Result<[u8; 32], VaultError> {
            if b.len() != 32 {
                return Err(VaultError::UnwrapFailed);
            }
            let mut k = [0; 32];
            for (i, (a, x)) in b.iter().zip(self.0).enumerate() {
                k[i] = a ^ x
            }
            Ok(k)
        }
    }
    // XOR adapter is test-only; never use for production key custody.
    #[test]
    fn authenticated_roundtrip_and_tamper() {
        let w = Fake([0xA5; 32]);
        let e = encrypt_file(&w, b"fixture", b"session/file").unwrap();
        assert_eq!(
            decrypt_file(&w, &e.envelope, &e.wrapped_dek, b"session/file").unwrap(),
            b"fixture"
        );
        assert_eq!(
            decrypt_file(&w, &e.envelope, &e.wrapped_dek, b"other").unwrap_err(),
            VaultError::AuthenticationFailed
        );
        let mut x = e.envelope.clone();
        *x.last_mut().unwrap() ^= 1;
        assert_eq!(
            decrypt_file(&w, &x, &e.wrapped_dek, b"session/file").unwrap_err(),
            VaultError::AuthenticationFailed
        )
    }
    #[test]
    fn rejects_malformed() {
        assert_eq!(
            decrypt_file(&Fake([0; 32]), b"bad", b"", b"").unwrap_err(),
            VaultError::InvalidEnvelope
        )
    }
}
