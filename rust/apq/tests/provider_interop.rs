//! Provider interop suite: everything that must agree across the two pinned providers
//! for mixed deployments (a Linux/awslc peer talking to an Apple/CryptoKit peer).
//!
//! Covers:
//!   1. `AwsLcCryptoProvider` runs a full PQ MLS group on suite 0xFDEA (ML-KEM-768) — the
//!      portable provider CI uses on Linux.
//!   2. The same provider covers the classical half (CURVE25519_CHACHA), so one provider
//!      selection serves both halves.
//!   3. (Apple targets) CryptoKit and awslc agree on the whole wire: raw KEM
//!      encap/decap, mixed-provider MLS groups, archive blobs, the HPKE envelope (the
//!      A.1 initial routing header), full APQ combiner sessions instantiated once per
//!      provider from the generic `CombinerClient` — establishment, APQ-PSK bind, app
//!      messaging — and an A.4 PQ ratchet round, all crossing providers in both
//!      directions with no multi-process harness.

// Test-only crate: helper fns aren't `#[test]` items, so the workspace's unwrap/panic
// denies would fire despite clippy.toml's allow-unwrap-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use mls_rs::client_builder::{ClientBuilder, MlsConfig};
use mls_rs::group::ReceivedMessage;
use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
use mls_rs::identity::SigningIdentity;
use mls_rs::{
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList, Group, MlsMessage,
};
use mls_rs_crypto_awslc::AwsLcCryptoProvider;

const ML_KEM_768: CipherSuite = CipherSuite::ML_KEM_768; // 65002 = 0xFDEA, matches ApqMode's suite

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

/// awslc drives a full ML-KEM-768 group end to end.
#[test]
fn awslc_pq_group_end_to_end() {
    let alice = build_client(AwsLcCryptoProvider::new(), ML_KEM_768, b"alice");
    let bob = build_client(AwsLcCryptoProvider::new(), ML_KEM_768, b"bob");
    group_round_trip(&alice, &bob);
}

/// awslc also covers the classical half (the suite apq's classical group runs on).
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

/// Interop tests — need CryptoKit, an Apple-only (platform-gated) dev-dependency.
#[cfg(any(target_os = "macos", target_os = "ios"))]
mod cryptokit_interop {
    use super::*;
    use apq::{
        create_combiner_send_group, join_combiner_group, pq_ratchet, CombinerClient, CryptoConfig,
    };
    use mls_rs::storage_provider::in_memory::InMemoryKeyPackageStorage;
    use mls_rs_crypto_awslc::MlKemKem;
    use mls_rs_crypto_cryptokit::ml_kem::MlKem768Kem;
    use mls_rs_crypto_cryptokit::{CryptoKitMlKemProvider, CryptoKitProvider};
    use mls_rs_crypto_traits::KemType;

    fn awslc_kem() -> MlKemKem {
        MlKemKem::new(ML_KEM_768).unwrap()
    }

    // Because `CombinerClient` is generic over its providers, ONE binary instantiates
    // both provider stacks and runs full combiner sessions between them — no
    // multi-process harness. This is the same generic client `two-mls-pq` pins to a
    // single provider per build.
    type AwsCombiner =
        CombinerClient<InMemoryKeyPackageStorage, AwsLcCryptoProvider, AwsLcCryptoProvider>;
    type CkCombiner =
        CombinerClient<InMemoryKeyPackageStorage, CryptoKitProvider, CryptoKitMlKemProvider>;

    fn aws_combiner(id: &[u8]) -> AwsCombiner {
        CombinerClient::new(id.to_vec(), CryptoConfig::default()).unwrap()
    }

    fn ck_combiner(id: &[u8]) -> CkCombiner {
        CombinerClient::new(
            id.to_vec(),
            CryptoConfig {
                classical: CryptoKitProvider::default(),
                pq: CryptoKitMlKemProvider,
                suite: Default::default(),
            },
        )
        .unwrap()
    }

    /// Raw ML-KEM-768 encap/decap crosses providers in both directions, i.e.
    /// encapsulation-key and ciphertext encodings agree (the pq_ratchet wire).
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

    /// A PQ MLS group with one awslc member and one CryptoKit member, group created from
    /// each side.
    #[test]
    fn pq_group_cross_provider_interop() {
        let awslc = build_client(AwsLcCryptoProvider::new(), ML_KEM_768, b"awslc");
        let cryptokit = build_client(CryptoKitMlKemProvider, ML_KEM_768, b"cryptokit");
        group_round_trip(&awslc, &cryptokit);
        group_round_trip(&cryptokit, &awslc);
    }

    /// A full APQ combiner session across providers, initiated from each side: the
    /// two-welcome establishment, the APQ-PSK bind (whose exporter-derived PSK must
    /// agree bit-for-bit across providers or the classical join fails), and app
    /// messaging both ways.
    #[test]
    fn combiner_establishment_crosses_providers() {
        // awslc initiates to a CryptoKit acceptor…
        let alice = aws_combiner(b"alice-awslc");
        let bob = ck_combiner(b"bob-cryptokit");
        let (mut a_send, welcome) = create_combiner_send_group(
            &bob.generate_classical_key_package().unwrap(),
            &bob.generate_pq_key_package().unwrap(),
            &alice,
            None,
        )
        .unwrap();
        let mut b_recv = join_combiner_group(&welcome, &bob).unwrap();
        send_and_check(&mut a_send.classical, &mut b_recv.classical, b"aws->ck");
        send_and_check(&mut b_recv.classical, &mut a_send.classical, b"ck->aws");

        // …and CryptoKit initiates to an awslc acceptor.
        let carol = ck_combiner(b"carol-cryptokit");
        let dave = aws_combiner(b"dave-awslc");
        let (mut c_send, welcome) = create_combiner_send_group(
            &dave.generate_classical_key_package().unwrap(),
            &dave.generate_pq_key_package().unwrap(),
            &carol,
            None,
        )
        .unwrap();
        let mut d_recv = join_combiner_group(&welcome, &dave).unwrap();
        send_and_check(&mut c_send.classical, &mut d_recv.classical, b"ck->aws");
        send_and_check(&mut d_recv.classical, &mut c_send.classical, b"aws->ck");
    }

    /// A full A.4 PQ ratchet round on a cross-provider session: each side runs its own
    /// provider's ML-KEM for the EK/ct exchange, then the pathless PQ commit and the
    /// classical apq-PSK bind cross providers. Messaging must still flow in the
    /// PQ-refreshed epoch.
    #[test]
    fn pq_ratchet_crosses_providers() {
        let alice = aws_combiner(b"alice-awslc");
        let bob = ck_combiner(b"bob-cryptokit");
        let (mut a_send, welcome) = create_combiner_send_group(
            &bob.generate_classical_key_package().unwrap(),
            &bob.generate_pq_key_package().unwrap(),
            &alice,
            None,
        )
        .unwrap();
        let mut b_recv = join_combiner_group(&welcome, &bob).unwrap();

        // EK/ct exchange, each side on its own provider's KEM.
        let eph = pq_ratchet::generate_ephemeral(&awslc_kem()).unwrap();
        let (s_bob, ct) =
            pq_ratchet::encapsulate(&MlKem768Kem::new(), &eph.encapsulation_key()).unwrap();
        let s_alice = pq_ratchet::decapsulate(&awslc_kem(), &eph, &ct).unwrap();
        assert_eq!(s_alice, s_bob);

        // Alice (awslc) binds: pathless PQ commit + classical apq-PSK commit.
        let a_stores = [alice.pq().secret_store(), alice.classical().secret_store()];
        let attestation = apq::component::ApqInfoUpdate {
            t_epoch: a_send.classical.current_epoch() + 1,
            pq_epoch: a_send.pq.as_ref().unwrap().current_epoch() + 1,
        };
        let pq_commit = pq_ratchet::inject_and_commit(
            a_send.pq.as_mut().unwrap(),
            &s_alice,
            &a_stores,
            attestation,
        )
        .unwrap();
        let apq_psk = pq_ratchet::export_apq_psk(a_send.pq.as_mut().unwrap(), &a_stores).unwrap();
        let cl_out = apq_psk
            .add_to_commit(a_send.classical.commit_builder())
            .unwrap()
            .build()
            .unwrap();
        a_send.classical.apply_pending_commit().unwrap();

        // Bob (CryptoKit) applies both commits; the applied PQ commit surfaces the
        // initiator's epoch attestation intact.
        let b_stores = [bob.pq().secret_store(), bob.classical().secret_store()];
        let (_, b_attestation) = pq_ratchet::apply_injected_commit(
            b_recv.pq.as_mut().unwrap(),
            &s_bob,
            &pq_commit,
            &b_stores,
        )
        .unwrap();
        assert_eq!(b_attestation, attestation);
        let cl = MlsMessage::from_bytes(&cl_out.commit_message.to_bytes().unwrap()).unwrap();
        b_recv.classical.process_incoming_message(cl).unwrap();

        send_and_check(
            &mut a_send.classical,
            &mut b_recv.classical,
            b"post-ratchet",
        );
        send_and_check(
            &mut b_recv.classical,
            &mut a_send.classical,
            b"post-ratchet-2",
        );
    }

    /// The HPKE envelope crosses providers in both directions — the mixed-deployment
    /// shape of `two-mls-pq`'s `hpke_seal_to_key_package` / `hpke_open`: the keypair
    /// stays with its generating provider (an invitation's init key), the peer seals
    /// to the public key with the other provider.
    #[test]
    fn hpke_envelope_crosses_providers() {
        let awslc_cs = AwsLcCryptoProvider::new()
            .cipher_suite_provider(ML_KEM_768)
            .unwrap();
        let ck_cs = CryptoKitMlKemProvider
            .cipher_suite_provider(ML_KEM_768)
            .unwrap();
        let (info, aad, pt): (&[u8], &[u8], &[u8]) = (b"client-id", b"aad", b"routing-header");

        // CryptoKit holds the keypair; awslc seals to it; CryptoKit opens.
        let (dk, ek) = ck_cs.kem_generate().unwrap();
        let sealed = awslc_cs.hpke_seal(&ek, info, Some(aad), pt).unwrap();
        let opened = ck_cs.hpke_open(&sealed, &dk, &ek, info, Some(aad)).unwrap();
        assert_eq!(&*opened, pt);

        // awslc holds the keypair; CryptoKit seals to it; awslc opens.
        let (dk, ek) = awslc_cs.kem_generate().unwrap();
        let sealed = ck_cs.hpke_seal(&ek, info, Some(aad), pt).unwrap();
        let opened = awslc_cs
            .hpke_open(&sealed, &dk, &ek, info, Some(aad))
            .unwrap();
        assert_eq!(&*opened, pt);
    }

    /// The archive blob format survives a provider swap: sealed with awslc's
    /// ChaCha20-Poly1305, opened with CryptoKit's (and vice versa).
    #[test]
    fn archive_blob_crosses_providers() {
        let awslc_cs = AwsLcCryptoProvider::new()
            .cipher_suite_provider(CipherSuite::CURVE25519_CHACHA)
            .unwrap();
        let ck_cs = CryptoKitProvider::default()
            .cipher_suite_provider(CipherSuite::CURVE25519_CHACHA)
            .unwrap();
        let key = vec![7u8; apq::archive::SEAL_KEY_LEN];

        let blob = apq::archive::seal(&awslc_cs, &key, b"cross-provider plaintext").unwrap();
        let pt = apq::archive::open(&ck_cs, &key, &blob).unwrap();
        assert_eq!(&*pt, b"cross-provider plaintext");

        let blob = apq::archive::seal(&ck_cs, &key, b"cross-provider plaintext").unwrap();
        let pt = apq::archive::open(&awslc_cs, &key, &blob).unwrap();
        assert_eq!(&*pt, b"cross-provider plaintext");
    }
}
