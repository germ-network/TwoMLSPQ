//! AEAD sealing for session archives. The caller supplies the cipher-suite provider that
//! runs the AEAD (a *classical* suite — the canonical choice is `CURVE25519_CHACHA`) and a
//! key of that suite's AEAD key size (held by the platform keystore); the sealed blob is
//! `nonce || AEAD(key, plaintext, aad = ARCHIVE_AAD || u16-BE suite)`. The AAD binds the
//! sealing suite, so a blob only opens under the suite that sealed it — a suite mismatch
//! fails authentication instead of silently attempting a cross-suite open. The blob
//! format is provider-independent: any provider implementing the same suite opens
//! another's blobs.
//!
//! Sealing is independent of the combiner construction, so it lives beside the storage
//! provider rather than in the session layer.

use mls_rs::CipherSuiteProvider;
use zeroize::Zeroizing;

use crate::{CombinerError, Result};

const ARCHIVE_AAD: &[u8] = b"twomlspq-archive-v1";

/// The AAD for one seal/open: the domain tag plus the sealing suite's u16 value, so the
/// suite is authenticated into the blob.
fn archive_aad<CS: CipherSuiteProvider>(cs: &CS) -> Vec<u8> {
    let mut aad = ARCHIVE_AAD.to_vec();
    aad.extend_from_slice(&u16::from(cs.cipher_suite()).to_be_bytes());
    aad
}

/// Length of the caller-supplied sealing key for the canonical `CURVE25519_CHACHA` suite
/// (ChaCha20-Poly1305 key size). `seal`/`open` validate against the supplied suite's actual
/// AEAD key size.
pub const SEAL_KEY_LEN: usize = 32;

/// Seal `plaintext` under `seal_key`, prepending a fresh random nonce.
pub fn seal<CS: CipherSuiteProvider>(
    cs: &CS,
    seal_key: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if seal_key.len() != cs.aead_key_size() {
        return Err(CombinerError::ArchiveInvalid);
    }
    let n = cs.aead_nonce_size();
    let mut out = vec![0u8; n];
    cs.random_bytes(&mut out).map_err(|_| CombinerError::Mls)?;
    let ct = cs
        .aead_seal(seal_key, plaintext, Some(&archive_aad(cs)), &out)
        .map_err(|_| CombinerError::Mls)?;
    out.reserve_exact(ct.len());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a blob produced by [`seal`] (with the same suite). Fails (no plaintext leaked) on a
/// wrong key or tampering (`DecryptionFailed`); a blob too short to even carry a nonce is
/// `ArchiveInvalid`.
pub fn open<CS: CipherSuiteProvider>(
    cs: &CS,
    seal_key: &[u8],
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if seal_key.len() != cs.aead_key_size() {
        return Err(CombinerError::ArchiveInvalid);
    }
    let n = cs.aead_nonce_size();
    if blob.len() < n {
        return Err(CombinerError::ArchiveInvalid);
    }
    let (nonce, ct) = blob.split_at(n);
    cs.aead_open(seal_key, ct, Some(&archive_aad(cs)), nonce)
        .map_err(|_| CombinerError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mls_rs::CryptoProvider;
    use mls_rs_crypto_awslc::AwsLcCryptoProvider;

    fn suite() -> impl CipherSuiteProvider {
        AwsLcCryptoProvider::new()
            .cipher_suite_provider(mls_rs::CipherSuite::CURVE25519_CHACHA)
            .unwrap()
    }

    fn key(b: u8) -> Vec<u8> {
        vec![b; SEAL_KEY_LEN]
    }

    #[test]
    fn test_seal_open_round_trips() {
        let cs = suite();
        let blob = seal(&cs, &key(7), b"hello archive").unwrap();
        assert_eq!(
            open(&cs, &key(7), &blob).unwrap().to_vec(),
            b"hello archive"
        );
    }

    #[test]
    fn test_open_with_wrong_key_fails() {
        let cs = suite();
        let blob = seal(&cs, &key(7), b"hello archive").unwrap();
        assert!(open(&cs, &key(8), &blob).is_err());
    }

    #[test]
    fn test_open_rejects_tampered_blob() {
        let cs = suite();
        let mut blob = seal(&cs, &key(7), b"hello archive").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xFF;
        assert!(open(&cs, &key(7), &blob).is_err());
    }

    #[test]
    fn test_seal_rejects_wrong_key_length() {
        assert!(seal(&suite(), &[0u8; 16], b"x").is_err());
    }

    #[test]
    fn test_open_under_different_suite_fails() {
        // CURVE25519_AES128 and P256_AES128 share the AEAD (AES-128-GCM) and key size, so
        // without the suite bound into the AAD this cross-suite open would SUCCEED.
        let seal_cs = AwsLcCryptoProvider::new()
            .cipher_suite_provider(mls_rs::CipherSuite::CURVE25519_AES128)
            .unwrap();
        let open_cs = AwsLcCryptoProvider::new()
            .cipher_suite_provider(mls_rs::CipherSuite::P256_AES128)
            .unwrap();
        let key = vec![7u8; seal_cs.aead_key_size()];
        let blob = seal(&seal_cs, &key, b"suite-bound").unwrap();
        assert!(matches!(
            open(&open_cs, &key, &blob),
            Err(CombinerError::DecryptionFailed)
        ));
        // Same suite still opens.
        assert_eq!(
            open(&seal_cs, &key, &blob).unwrap().to_vec(),
            b"suite-bound"
        );
    }
}
