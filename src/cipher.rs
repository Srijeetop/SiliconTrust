/// Phase 3 — Cipher layer
///
/// XChaCha20-Poly1305 authenticated encryption.
/// Nonce = first 24 bytes of BLAKE3(plaintext) — deterministic, stateless.
///
/// Ciphertext format:
///   [ 4  bytes ] magic "HEC\x01"
///   [ 16 bytes ] Argon2 salt  (random, public — needed to re-derive key)
///   [ 24 bytes ] XChaCha nonce = BLAKE3(plaintext)
///   [ N  bytes ] XChaCha20-Poly1305 ciphertext + 16-byte Poly1305 tag

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use zeroize::Zeroize;
use crate::fingerprint::DerivedKey;

pub const MAGIC: &[u8; 4] = b"STC\x01";
pub const SALT_LEN:   usize = 16;
pub const NONCE_LEN:  usize = 24;
pub const HEADER_LEN: usize = 4 + SALT_LEN + NONCE_LEN; // 44 bytes

#[derive(Debug)]
pub enum CipherError {
    BadMagic,
    TruncatedHeader,
    DecryptionFailed,
}

impl std::fmt::Display for CipherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CipherError::BadMagic         => write!(f, "Not a valid STCS file (bad magic)"),
            CipherError::TruncatedHeader  => write!(f, "File is truncated"),
            CipherError::DecryptionFailed => write!(f, "Decryption failed — wrong machine or corrupted file"),
        }
    }
}

/// Encrypt plaintext; embed salt in header so decryption can re-derive the key.
pub fn encrypt_with_salt(key: &DerivedKey, salt: &[u8; SALT_LEN], plaintext: &[u8]) -> Vec<u8> {
    let nonce_bytes: [u8; NONCE_LEN] = {
        let hash = blake3::hash(plaintext);
        let mut n = [0u8; NONCE_LEN];
        n.copy_from_slice(&hash.as_bytes()[..NONCE_LEN]);
        n
    };

    let cipher = XChaCha20Poly1305::new_from_slice(&key.0).expect("32-byte key");
    let nonce   = XNonce::from_slice(&nonce_bytes);
    let ct      = cipher.encrypt(nonce, plaintext).expect("encryption failed");

    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    out
}

/// Decrypt a blob produced by encrypt_with_salt. Wipes key on success.
pub fn decrypt(key: &mut DerivedKey, blob: &[u8]) -> Result<Vec<u8>, CipherError> {
    if blob.len() < HEADER_LEN    { return Err(CipherError::TruncatedHeader); }
    if &blob[..4] != MAGIC        { return Err(CipherError::BadMagic); }

    let nonce_bytes = &blob[4 + SALT_LEN .. 4 + SALT_LEN + NONCE_LEN];
    let ciphertext  = &blob[HEADER_LEN..];

    let cipher  = XChaCha20Poly1305::new_from_slice(&key.0).expect("32-byte key");
    let nonce   = XNonce::from_slice(nonce_bytes);
    let result  = cipher.decrypt(nonce, ciphertext).map_err(|_| CipherError::DecryptionFailed)?;

    key.0.zeroize();
    Ok(result)
}

/// Pull the Argon2 salt out of the header (needed before key derivation).
pub fn extract_salt(blob: &[u8]) -> Result<[u8; SALT_LEN], CipherError> {
    if blob.len() < HEADER_LEN { return Err(CipherError::TruncatedHeader); }
    if &blob[..4] != MAGIC     { return Err(CipherError::BadMagic); }
    let mut s = [0u8; SALT_LEN];
    s.copy_from_slice(&blob[4..4 + SALT_LEN]);
    Ok(s)
}
