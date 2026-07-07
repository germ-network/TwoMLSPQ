//! Phase 0 spike for the provider-agnostic plan (THROWAWAY — delete before Phase 1 lands).
//!
//! Proves, before any refactoring starts:
//!   1. `AwsLcCryptoProvider` runs a full PQ MLS group on suite 0xFDEA (ML-KEM-768) — the
//!      portable PQ provider CI needs on Linux.
//!   2. The same provider covers the classical half (CURVE25519_CHACHA), so one provider
//!      selection serves both halves and RustCrypto can be dropped.
//!   3. The archive blob format is provider-independent: a blob sealed by the current
//!      RustCrypto-backed `archive::seal` opens under awslc's AEAD.
//!   4. (cryptokit builds) CryptoKit and awslc agree on the ML-KEM-768 wire: raw KEM
//!      encap/decap crosses providers, and a group with one member on each provider works.

use mls_rs::client_builder::{ClientBuilder, MlsConfig};
use mls_rs::group::ReceivedMessage;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::identity::SigningIdentity;
use mls_rs::{
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList, Group, MlsMessage,
};
use mls_rs_crypto_awslc::AwsLcCryptoProvider;

const ML_KEM_768: CipherSuite = CipherSuite::ML_KEM_768; // 65002 = 0xFDEA, matches apq's const

fn build_client<P: CryptoProvider + Clone + 'static>(
    provider: P,
    suite: CipherSuite,
    name: &[u8],
) -> Client<impl MlsConfig> {
    let cs = provider.cipher_suite_provider(suite).unwrap();
    let (sk, pk) = cs.signature_key_generate().unwrap();
    let signing = SigningIdentity::new(BasicCredential::new(name.to_vec()).into_credential(), pk);
    ClientBuilder::new()
        .crypto_provider(provider)
        .identity_provider(BasicIdentityProvider::new())
        .signing_identity(signing, sk, suite)
        .build()
}

/// Alice creates a group, adds Bob by key package; both exchange an application message.
fn group_round_trip<A: MlsConfig, B: MlsConfig>(alice: &Client<A>, bob: &Client<B>) {
    let bob_kp = bob
        .generate_key_package_message(ExtensionList::new(), ExtensionList::new(), None)
        .unwrap();

    let mut alice_group = alice
        .create_group(ExtensionList::new(), ExtensionList::new(), None)
        .unwrap();
    let commit = alice_group
        .commit_builder()
        .add_member(bob_kp)
        .unwrap()
        .build()
        .unwrap();
    alice_group.apply_pending_commit().unwrap();

    let welcome = commit.welcome_messages.first().unwrap().clone();
    let (mut bob_group, _) = bob.join_group(None, &welcome, None).unwrap();

    send_and_check(&mut alice_group, &mut bob_group, b"alice->bob");
    send_and_check(&mut bob_group, &mut alice_group, b"bob->alice");
}

fn send_and_check<S: MlsConfig, R: MlsConfig>(
    sender: &mut Group<S>,
    receiver: &mut Group<R>,
    msg: &[u8],
) {
    let ct = sender
        .encrypt_application_message(msg, vec![])
        .unwrap()
        .to_bytes()
        .unwrap();
    let received = receiver
        .process_incoming_message(MlsMessage::from_bytes(&ct).unwrap())
        .unwrap();
    match received {
        ReceivedMessage::ApplicationMessage(m) => assert_eq!(m.data(), msg),
        other => panic!("expected application message, got {other:?}"),
    }
}

/// Spike goal 1: awslc drives a full ML-KEM-768 group end to end.
#[test]
fn awslc_pq_group_end_to_end() {
    let alice = build_client(AwsLcCryptoProvider::new(), ML_KEM_768, b"alice");
    let bob = build_client(AwsLcCryptoProvider::new(), ML_KEM_768, b"bob");
    group_round_trip(&alice, &bob);
}

/// Spike goal 2: awslc also covers the classical half (suite used by apq's classical group).
#[test]
fn awslc_classical_group_end_to_end() {
    let alice = build_client(
        AwsLcCryptoProvider::new(),
        CipherSuite::CURVE25519_CHACHA,
        b"alice",
    );
    let bob = build_client(
        AwsLcCryptoProvider::new(),
        CipherSuite::CURVE25519_CHACHA,
        b"bob",
    );
    group_round_trip(&alice, &bob);
}

/// Spike goal 3: the archive blob format survives a provider swap. Seal with the current
/// RustCrypto-backed `apq::archive::seal`, open manually with awslc's ChaCha20-Poly1305.
/// (AAD duplicated from archive.rs — private there, and this test is throwaway.)
#[test]
fn awslc_opens_rustcrypto_sealed_archive() {
    const ARCHIVE_AAD: &[u8] = b"twomlspq-archive-v1";
    let key = vec![7u8; apq::archive::SEAL_KEY_LEN];
    let blob = apq::archive::seal(&key, b"cross-provider plaintext").unwrap();

    let cs = AwsLcCryptoProvider::new()
        .cipher_suite_provider(CipherSuite::CURVE25519_CHACHA)
        .unwrap();
    let (nonce, ct) = blob.split_at(cs.aead_nonce_size());
    let pt = cs.aead_open(&key, ct, Some(ARCHIVE_AAD), nonce).unwrap();
    assert_eq!(&*pt, b"cross-provider plaintext");
}

/// Interop tests — need CryptoKit, so only on `--features cryptokit` (Apple targets).
#[cfg(feature = "cryptokit")]
mod cryptokit_interop {
    use super::*;
    use mls_rs_crypto_awslc::MlKemKem;
    use mls_rs_crypto_cryptokit::ml_kem::MlKem768Kem;
    use mls_rs_crypto_cryptokit::CryptoKitMlKemProvider;
    use mls_rs_crypto_traits::KemType;

    fn awslc_kem() -> MlKemKem {
        MlKemKem::new(ML_KEM_768).unwrap()
    }

    /// Spike goal 4a: raw ML-KEM-768 encap/decap crosses providers in both directions,
    /// i.e. encapsulation-key and ciphertext encodings agree (the pq_ratchet wire).
    #[test]
    fn kem_cross_provider_encap_decap() {
        // CryptoKit generates; awslc encapsulates; CryptoKit decapsulates.
        let ck = MlKem768Kem::new();
        let (dk, ek) = ck.generate().unwrap();
        let res = awslc_kem().encap(&ek).unwrap();
        let s = ck.decap(&res.enc, &dk, &ek).unwrap();
        assert_eq!(s, res.shared_secret);

        // awslc generates; CryptoKit encapsulates; awslc decapsulates.
        let al = awslc_kem();
        let (dk, ek) = al.generate().unwrap();
        let res = MlKem768Kem::new().encap(&ek).unwrap();
        let s = al.decap(&res.enc, &dk, &ek).unwrap();
        assert_eq!(s, res.shared_secret);
    }

    /// Spike goal 4b: a PQ MLS group with one awslc member and one CryptoKit member,
    /// group created from each side.
    #[test]
    fn pq_group_cross_provider_interop() {
        let awslc = build_client(AwsLcCryptoProvider::new(), ML_KEM_768, b"awslc");
        let cryptokit = build_client(CryptoKitMlKemProvider, ML_KEM_768, b"cryptokit");
        group_round_trip(&awslc, &cryptokit);
        group_round_trip(&cryptokit, &awslc);
    }
}
