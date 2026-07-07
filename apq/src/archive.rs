//! AEAD sealing for session archives. The caller supplies a 32-byte key (held by the platform
//! keystore); the sealed blob is `nonce || ChaCha20Poly1305(key, plaintext, aad = ARCHIVE_AAD)`.
//! Sealing is independent of the combiner construction, so it lives beside the storage provider
//! rather than in the session layer, which has no direct crypto-provider dependency.

use mls_rs::{CipherSuiteProvider, CryptoProvider};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use zeroize::Zeroizing;

use crate::{CombinerError, Result};

const ARCHIVE_AAD: &[u8] = b"twomlspq-archive-v1";

/// Length of the caller-supplied sealing key (ChaCha20-Poly1305 key size).
pub const SEAL_KEY_LEN: usize = 32;

fn aead() -> Result<impl CipherSuiteProvider> {
    RustCryptoProvider::new()
        .cipher_suite_provider(mls_rs::CipherSuite::CURVE25519_CHACHA)
        .ok_or(CombinerError::Mls)
}

/// Seal `plaintext` under `seal_key`, prepending a fresh random nonce.
pub fn seal(seal_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if seal_key.len() != SEAL_KEY_LEN {
        return Err(CombinerError::Mls);
    }
    let cs = aead()?;
    let mut nonce = vec![0u8; cs.aead_nonce_size()];
    cs.random_bytes(&mut nonce)
        .map_err(|_| CombinerError::Mls)?;
    let ct = cs
        .aead_seal(seal_key, plaintext, Some(ARCHIVE_AAD), &nonce)
        .map_err(|_| CombinerError::Mls)?;
    let mut out = nonce;
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a blob produced by [`seal`]. Fails (no plaintext leaked) on a wrong key or tampering.
pub fn open(seal_key: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if seal_key.len() != SEAL_KEY_LEN {
        return Err(CombinerError::Mls);
    }
    let cs = aead()?;
    let n = cs.aead_nonce_size();
    if blob.len() < n {
        return Err(CombinerError::Mls);
    }
    let (nonce, ct) = blob.split_at(n);
    cs.aead_open(seal_key, ct, Some(ARCHIVE_AAD), nonce)
        .map_err(|_| CombinerError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> Vec<u8> {
        vec![b; SEAL_KEY_LEN]
    }

    #[test]
    fn test_seal_open_round_trips() {
        let blob = seal(&key(7), b"hello archive").unwrap();
        assert_eq!(open(&key(7), &blob).unwrap().to_vec(), b"hello archive");
    }

    #[test]
    fn test_open_with_wrong_key_fails() {
        let blob = seal(&key(7), b"hello archive").unwrap();
        assert!(open(&key(8), &blob).is_err());
    }

    #[test]
    fn test_open_rejects_tampered_blob() {
        let mut blob = seal(&key(7), b"hello archive").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xFF;
        assert!(open(&key(7), &blob).is_err());
    }

    #[test]
    fn test_seal_rejects_wrong_key_length() {
        assert!(seal(&[0u8; 16], b"x").is_err());
    }
}
