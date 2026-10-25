//! Payload encryption with XChaCha20-Poly1305.
//!
//! This module is independent from the rest of the engine: it takes plain bytes
//! and returns an [`EncryptedPayload`] with everything the stub needs to embed
//! it into the final binary.
//!
//! We use an AEAD (Authenticated Encryption with Associated Data): the
//! ciphertext includes a 16-byte Poly1305 tag that guarantees integrity and
//! authenticity. Any tampering or a wrong key produces an error in
//! [`decrypt_payload`], never a `panic`.
//!
//! We use the XChaCha20 variant (24-byte nonce) instead of standard ChaCha20
//! (12-byte nonce): the longer nonce allows generating it randomly per message
//! with no practical collision risk, without needing a global counter.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};
use rand::RngCore;

/// Key size (256 bits).
pub const KEY_LEN: usize = 32;
/// XChaCha20 nonce size (192 bits).
pub const NONCE_LEN: usize = 24;

/// Encrypted payload ready to be embedded into the stub.
///
/// We do not derive `Debug`: we implement one by hand that hides the key, so
/// an accidental `{:?}` does not leak it into logs.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedPayload {
    /// Ciphertext + trailing 16-byte Poly1305 tag.
    pub ciphertext: Vec<u8>,
    /// XChaCha20 nonce (24 bytes), unique per encryption.
    pub nonce: [u8; NONCE_LEN],
    /// Symmetric key (32 bytes).
    pub key: [u8; KEY_LEN],
    /// Original payload size, for validation and reservation in the stub.
    pub plaintext_len: usize,
}

impl std::fmt::Debug for EncryptedPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedPayload")
            .field("ciphertext_len", &self.ciphertext.len())
            .field("nonce", &hex::encode(self.nonce))
            .field("key", &"[REDACTED]")
            .field("plaintext_len", &self.plaintext_len)
            .finish()
    }
}

/// Crypto module error.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// Encryption failed. With fixed key/nonce sizes this should not happen.
    #[error("encryption error")]
    Encryption,

    /// Decryption failed: wrong key or tampered ciphertext.
    ///
    /// XChaCha20-Poly1305 does not distinguish between the two causes: in both
    /// cases the Poly1305 tag verification fails. It is only compiled in
    /// tests; production decryption is done by the stub at runtime.
    #[cfg(test)]
    #[error("decryption error: wrong key or tampered ciphertext")]
    Decryption,
}

/// Local alias: `Result` with [`CryptoError`] as the error type.
type Result<T> = std::result::Result<T, CryptoError>;

/// Generates a 256-bit symmetric key using the system CSPRNG.
///
/// Builds derive their key from [`crate::engine::entropy::BuildEntropy`]; this
/// stays as the API for tests and out-of-tree callers.
#[allow(dead_code)]
pub fn generate_key() -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

/// Generates a random 192-bit nonce.
#[allow(dead_code)]
fn generate_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Encrypts `plaintext` with `key`, generating a fresh random nonce.
///
/// An empty payload is a valid case: it encrypts to a ciphertext that only
/// contains the authentication tag (16 bytes). Builds use
/// [`encrypt_payload_with_nonce`]; this remains the convenience API.
#[allow(dead_code)]
pub fn encrypt_payload(plaintext: &[u8], key: &[u8; KEY_LEN]) -> Result<EncryptedPayload> {
    let nonce = generate_nonce();
    encrypt_payload_with_nonce(plaintext, key, &nonce)
}

/// Encrypts `plaintext` with an explicit key and nonce.
///
/// This is the replay path: a build records both values, so feeding them back
/// must reproduce the ciphertext byte for byte. The nonce is never derived
/// here; the caller owns it (the build derives it from
/// [`crate::engine::entropy::BuildEntropy`]).
pub fn encrypt_payload_with_nonce(
    plaintext: &[u8],
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Result<EncryptedPayload> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));

    let ciphertext = cipher
        .encrypt(XNonce::from_slice(nonce), plaintext)
        .map_err(|_| CryptoError::Encryption)?;

    Ok(EncryptedPayload {
        ciphertext,
        nonce: *nonce,
        key: *key,
        plaintext_len: plaintext.len(),
    })
}

/// Decrypts an [`EncryptedPayload`].
///
/// Only for tests/verification in this phase: the generated stub performs its
/// own decryption at runtime.
#[cfg(test)]
pub fn decrypt_payload(enc: &EncryptedPayload) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&enc.key));
    let plaintext = cipher
        .decrypt(XNonce::from_slice(&enc.nonce), enc.ciphertext.as_ref())
        .map_err(|_| CryptoError::Decryption)?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_empty_payload() {
        let key = generate_key();
        let enc = encrypt_payload(&[], &key).expect("encrypt empty payload");
        assert_eq!(enc.plaintext_len, 0);

        let dec = decrypt_payload(&enc).expect("decrypt empty payload");
        assert!(dec.is_empty());
    }

    #[test]
    fn round_trip_one_byte() {
        let key = generate_key();
        let plaintext = [0x42u8];

        let enc = encrypt_payload(&plaintext, &key).expect("encrypt 1 byte");
        let dec = decrypt_payload(&enc).expect("decrypt 1 byte");

        assert_eq!(dec, plaintext);
    }

    #[test]
    fn round_trip_one_megabyte() {
        let key = generate_key();
        // Deterministic 1 MB pattern (realistic PE-sized case).
        let plaintext: Vec<u8> = (0..1_000_000u32).map(|i| (i % 251) as u8).collect();

        let enc = encrypt_payload(&plaintext, &key).expect("encrypt 1 MB");
        assert_eq!(enc.plaintext_len, plaintext.len());

        let dec = decrypt_payload(&enc).expect("decrypt 1 MB");
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn nonce_is_unique_per_encryption() {
        let key = generate_key();
        let a = encrypt_payload(b"hola", &key).expect("encrypt a");
        let b = encrypt_payload(b"hola", &key).expect("encrypt b");

        assert_ne!(
            a.nonce, b.nonce,
            "two encryptions must use different nonces"
        );
    }

    #[test]
    fn nonce_has_xchacha_length() {
        let key = generate_key();
        let enc = encrypt_payload(b"hola", &key).expect("encrypt");
        assert_eq!(enc.nonce.len(), 24, "the XChaCha20 nonce must be 24 bytes");
    }

    #[test]
    fn rejects_tampered_ciphertext() {
        let key = generate_key();
        let mut enc = encrypt_payload(b"secret payload", &key).expect("encrypt");

        // Flip one byte of the ciphertext (inside the Poly1305 tag).
        let last = enc.ciphertext.len() - 1;
        enc.ciphertext[last] ^= 0x01;

        assert!(
            decrypt_payload(&enc).is_err(),
            "a tampered ciphertext must fail authentication"
        );
    }

    #[test]
    fn rejects_wrong_key() {
        let key = generate_key();
        let mut enc = encrypt_payload(b"secret payload", &key).expect("encrypt");

        // Derive a different key deterministically (without relying on
        // `generate_key` producing a different value).
        enc.key[0] ^= 0xFF;

        assert!(
            decrypt_payload(&enc).is_err(),
            "a wrong key must fail decryption"
        );
    }

    #[test]
    fn ciphertext_is_plaintext_plus_tag() {
        let key = generate_key();
        let plaintext = b"data";

        let enc = encrypt_payload(plaintext, &key).expect("encrypt");

        // The ciphertext adds the 16-byte Poly1305 tag.
        assert_eq!(enc.ciphertext.len(), plaintext.len() + 16);
    }

    #[test]
    fn an_explicit_nonce_is_preserved_and_reproduces_the_bytes() {
        let key = [0x11u8; KEY_LEN];
        let nonce = [0x22u8; NONCE_LEN];
        let first =
            encrypt_payload_with_nonce(b"replay me", &key, &nonce).expect("first encryption");
        let second =
            encrypt_payload_with_nonce(b"replay me", &key, &nonce).expect("second encryption");

        assert_eq!(first.nonce, nonce);
        assert_eq!(first.key, key);
        assert_eq!(first.ciphertext, second.ciphertext);
    }
}
