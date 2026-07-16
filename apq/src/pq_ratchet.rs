//! Germ PQ ratchet (two-mls-pq book: Protocol Flows §A.3): fresh ML-KEM entropy is injected into
//! the PQ group via a *pathless* PSK commit, then re-exported into the classical group, so the
//! whole bind is cheap and staple-able to an app message — no per-round PQ updatePath.
//!
//! The initiator sends an encapsulation key (EK), the responder encapsulates a fresh shared
//! secret S and returns the ciphertext, and the initiator decapsulates. Both sides then inject S
//! as a PSK into the PQ group (a commit with no updatePath) and re-export the `apq_psk` from the
//! resulting epoch to bind into the classical group.
//!
//! Provider-agnostic: the KEM steps are generic over [`KemType`]; the caller supplies its
//! provider's ML-KEM (e.g. CryptoKit's `MlKem768Kem`, aws-lc's `MlKemKem`). Both sides must
//! of course run the same KEM — the one belonging to the PQ group's cipher suite.

use mls_rs::client_builder::MlsConfig;
use mls_rs::crypto::{HpkePublicKey, HpkeSecretKey};
use mls_rs::psk::{ExternalPskId, PreSharedKey};
use mls_rs::storage_provider::in_memory::InMemoryPreSharedKeyStorage;
use mls_rs::{Group, MlsMessage};
use mls_rs_crypto_traits::KemType;
use zeroize::Zeroizing;

use crate::component::{commit_attestation, ApqInfoUpdate};
use crate::group::{export_psk, injected_secret_psk_id, ExportedPsk, PskDomain};
use crate::{CombinerError, Result};

/// Initiator-side ephemeral for one PQ ratchet round. Holds the decapsulation key; the
/// encapsulation key is what goes on the wire. Dropped (zeroizing the DK) once the round binds.
pub struct PqEphemeral {
    dk: HpkeSecretKey,
    ek: HpkePublicKey,
}

impl PqEphemeral {
    pub fn encapsulation_key(&self) -> Vec<u8> {
        self.ek.as_ref().to_vec()
    }

    /// The decapsulation (secret) key bytes, kept `Zeroizing`. The one piece of held
    /// state an initiator-side mid-round session archive must persist so
    /// [`decapsulate`] still recovers S after the restore; pairs with
    /// [`encapsulation_key`](Self::encapsulation_key) and [`from_bytes`](Self::from_bytes).
    pub fn decapsulation_key(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.dk.as_ref().to_vec())
    }

    /// Rebuild an ephemeral from its serialised decapsulation and encapsulation key
    /// bytes (an initiator-side mid-A.3 archive restore). The bytes are wrapped, not
    /// validated: a corrupt pair simply fails to recover the peer's S in [`decapsulate`].
    pub fn from_bytes(dk: &[u8], ek: &[u8]) -> Self {
        Self {
            dk: HpkeSecretKey::from(dk.to_vec()),
            ek: HpkePublicKey::from(ek.to_vec()),
        }
    }
}

/// Initiator step 1 — generate a fresh KEM keypair.
pub fn generate_ephemeral<K: KemType>(kem: &K) -> Result<PqEphemeral> {
    let (dk, ek) = kem.generate().map_err(|_| CombinerError::Mls)?;
    Ok(PqEphemeral { dk, ek })
}

/// Responder — encapsulate to the initiator's EK, returning `(shared_secret S, ciphertext ct)`.
pub fn encapsulate<K: KemType>(kem: &K, ek_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let ek = HpkePublicKey::from(ek_bytes.to_vec());
    let res = kem.encap(&ek).map_err(|_| CombinerError::Mls)?;
    Ok((res.shared_secret.to_vec(), res.enc.to_vec()))
}

/// Initiator step 2 — decapsulate the responder's `ct` with the held DK, recovering S.
pub fn decapsulate<K: KemType>(kem: &K, eph: &PqEphemeral, ct: &[u8]) -> Result<Vec<u8>> {
    kem.decap(ct, &eph.dk, &eph.ek)
        .map_err(|_| CombinerError::Mls)
}

/// PSK id for the injected secret S at the PQ group's current epoch. The trailing domain byte
/// (see `group::PSK_DOMAIN_INJECTED`) keeps it disjoint from any exported `apq_psk` id, which is
/// derived from the *next* epoch and carries no domain byte.
fn injected_psk_id<Cfg: MlsConfig>(group: &Group<Cfg>) -> ExternalPskId {
    injected_secret_psk_id(group.current_epoch(), group.group_id())
}

/// Holds an injected secret S registered in the given PSK stores and removes it on drop, so the
/// per-round ML-KEM entropy is cleared on **every** exit path — including early `?` returns — not
/// just the happy path. This is what gives the ratchet forward secrecy: a later state compromise
/// cannot recover S. `id` is reused for the commit's `add_external_psk` proposal.
///
/// The stores are the caller's registry of every store its groups resolve PSKs from (an mls-rs
/// group reads the store of the client that created it, which an agent rotation may have
/// replaced as the session's current client).
struct InjectedSecret<'a> {
    id: ExternalPskId,
    stores: &'a [InMemoryPreSharedKeyStorage],
}

impl<'a> InjectedSecret<'a> {
    fn register<Cfg: MlsConfig>(
        group: &Group<Cfg>,
        s: &[u8],
        stores: &'a [InMemoryPreSharedKeyStorage],
    ) -> Self {
        let id = injected_psk_id(group);
        crate::group::register_psk_stores(stores, &id, &PreSharedKey::new(s.to_vec()));
        Self { id, stores }
    }
}

impl Drop for InjectedSecret<'_> {
    fn drop(&mut self) {
        for store in self.stores {
            store.clone().delete(&self.id);
        }
    }
}

/// Initiator (committer) — inject S into `pq_group` via a pathless PSK commit carrying the
/// -02 `AppDataUpdate` epoch attestation, apply it, and re-export the `apq_psk` from the
/// new PQ epoch (registered for the classical bind). The injected secret S stays an
/// *external* PSK (it is externally-sourced KEM entropy, not an exporter-derived value);
/// the re-exported `apq_psk` is an application PSK.
/// Returns `(pq_commit_bytes, apq_psk)`.
pub fn inject_and_commit<Cfg: MlsConfig>(
    pq_group: &mut Group<Cfg>,
    s: &[u8],
    stores: &[InMemoryPreSharedKeyStorage],
    attestation: ApqInfoUpdate,
) -> Result<(Vec<u8>, ExportedPsk)> {
    let secret = InjectedSecret::register(pq_group, s, stores);
    let out = pq_group
        .commit_builder()
        .add_external_psk(secret.id.clone())
        .map_err(|_| CombinerError::Mls)?
        .custom_proposal(attestation.to_custom_proposal()?)
        .build()
        .map_err(|_| CombinerError::Mls)?;
    pq_group
        .apply_pending_commit()
        .map_err(|_| CombinerError::Mls)?;
    crate::group::ensure_two_party(pq_group)?;
    // S is now folded into the new epoch; wipe it from the stores before re-exporting.
    drop(secret);
    let apq_psk = export_psk(pq_group, PskDomain::Apq)?;
    crate::group::register_psk_stores(stores, apq_psk.storage_id(), apq_psk.psk());
    let bytes = out
        .commit_message
        .to_bytes()
        .map_err(|_| CombinerError::Mls)?;
    Ok((bytes, apq_psk))
}

/// Responder (applier) — register S (held since `encapsulate`), apply the initiator's pathless PQ
/// commit, and re-export the same `apq_psk` from the new PQ epoch.
///
/// Returns the id together with the commit's -02 `AppDataUpdate` attestation, which is
/// mandatory on this half of a FULL: its absence (or a non-commit in the slot) fails with
/// [`CombinerError::ApqInfoMismatch`] before any secret is re-exported. The caller
/// verifies the attested epochs against both halves once the classical commit has
/// applied too.
pub fn apply_injected_commit<Cfg: MlsConfig>(
    pq_group: &mut Group<Cfg>,
    s: &[u8],
    pq_commit: &[u8],
    stores: &[InMemoryPreSharedKeyStorage],
) -> Result<(ExportedPsk, ApqInfoUpdate)> {
    let secret = InjectedSecret::register(pq_group, s, stores);
    let msg = MlsMessage::from_bytes(pq_commit).map_err(|_| CombinerError::Mls)?;
    let received = pq_group
        .process_incoming_message(msg)
        .map_err(|_| CombinerError::Mls)?;
    let attestation = match &received {
        mls_rs::group::ReceivedMessage::Commit(desc) => {
            commit_attestation(desc)?.ok_or(CombinerError::ApqInfoMismatch)?
        }
        _ => return Err(CombinerError::ApqInfoMismatch),
    };
    crate::group::ensure_two_party(pq_group)?;
    // S is now folded into the new epoch; wipe it before re-exporting.
    drop(secret);
    let apq_psk = export_psk(pq_group, PskDomain::Apq)?;
    crate::group::register_psk_stores(stores, apq_psk.storage_id(), apq_psk.psk());
    Ok((apq_psk, attestation))
}

/// Benchmark fixture (never enabled in production): the "old" APQ-faithful per-round PQ cost — a
/// self-Update commit on a PQ group carrying a full updatePath (leaf + path keys + ciphertext),
/// for comparison against the pathless PSK-injection commit. Uses a path-required client to
/// force the updatePath. The caller supplies its PQ provider and suite (see `ApqMode`).
#[cfg(feature = "benchmark_util")]
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub fn full_pq_updatepath_commit_size<P>(provider: P, suite: mls_rs::CipherSuite) -> usize
where
    P: mls_rs::CryptoProvider + Clone,
{
    use mls_rs::client_builder::ClientBuilder;
    use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
    use mls_rs::identity::SigningIdentity;
    use mls_rs::mls_rules::{CommitOptions, DefaultMlsRules};
    use mls_rs::{CipherSuiteProvider, ExtensionList};

    let rules =
        DefaultMlsRules::new().with_commit_options(CommitOptions::new().with_path_required(true));
    let build = |rules: DefaultMlsRules| {
        let cs = provider.cipher_suite_provider(suite).unwrap();
        let (sk, pk) = cs.signature_key_generate().unwrap();
        let signing = SigningIdentity::new(
            BasicCredential::new(pk.as_ref().to_vec()).into_credential(),
            pk,
        );
        ClientBuilder::new()
            .crypto_provider(provider.clone())
            .identity_provider(BasicIdentityProvider::new())
            .mls_rules(rules)
            .signing_identity(signing, sk, suite)
            .build()
    };
    let alice = build(rules.clone());
    let bob = build(rules);
    let bob_kp = bob
        .generate_key_package_message(ExtensionList::new(), ExtensionList::new(), None)
        .unwrap()
        .to_bytes()
        .unwrap();
    let mut group = alice
        .create_group(ExtensionList::new(), ExtensionList::new(), None)
        .unwrap();
    group
        .commit_builder()
        .add_member(MlsMessage::from_bytes(&bob_kp).unwrap())
        .unwrap()
        .build()
        .unwrap();
    group.apply_pending_commit().unwrap();
    let out = group.commit_builder().build().unwrap();
    out.commit_message.to_bytes().unwrap().len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::{create_combiner_send_group, join_combiner_group};
    use crate::{ApqCipherSuite, CombinerClient, CryptoConfig};
    use mls_rs::storage_provider::in_memory::InMemoryKeyPackageStorage;
    use mls_rs::{CipherSuiteProvider, CryptoProvider};
    use mls_rs_crypto_awslc::{AwsLcCryptoProvider, MlKemKem};

    fn client(
    ) -> CombinerClient<InMemoryKeyPackageStorage, AwsLcCryptoProvider, AwsLcCryptoProvider> {
        // A fresh, unique ClientId for tests (opaque random bytes, not a signing key).
        let cs = AwsLcCryptoProvider::new()
            .cipher_suite_provider(mls_rs::CipherSuite::CURVE25519_CHACHA)
            .unwrap();
        let (client_id, _) = cs.signature_key_generate().unwrap();
        CombinerClient::new(client_id.as_bytes().to_vec(), CryptoConfig::default()).unwrap()
    }

    /// The test KEM: aws-lc's ML-KEM-768, matching the default suite pair's PQ half.
    fn kem() -> MlKemKem {
        MlKemKem::new(ApqCipherSuite::default().pq).unwrap()
    }

    #[test]
    fn test_kem_encapsulate_decapsulate_round_trips() {
        let eph = generate_ephemeral(&kem()).unwrap();
        let ek = eph.encapsulation_key();
        assert_eq!(ek.len(), 1184, "ML-KEM-768 EK is 1184 bytes");

        let (s_bob, ct) = encapsulate(&kem(), &ek).unwrap();
        assert_eq!(ct.len(), 1088, "ML-KEM-768 ciphertext is 1088 bytes");
        assert_eq!(s_bob.len(), 32, "ML-KEM-768 shared secret is 32 bytes");

        let s_alice = decapsulate(&kem(), &eph, &ct).unwrap();
        assert_eq!(s_alice, s_bob, "both sides derive the same shared secret");
    }

    #[test]
    fn test_pq_ratchet_binds_fresh_entropy_into_both_groups() {
        let alice = client();
        let bob = client();

        let (mut asg, welcome) = create_combiner_send_group(
            &bob.generate_classical_key_package().unwrap(),
            &bob.generate_pq_key_package().unwrap(),
            &alice,
            None,
        )
        .unwrap();
        let mut bob_recv = join_combiner_group(&welcome, &bob).unwrap();

        let pq_epoch_before = asg.pq.as_ref().unwrap().current_epoch();
        let cl_epoch_before = asg.classical.current_epoch();

        // EK/ct exchange: Alice initiates, Bob responds, Alice recovers S.
        let eph = generate_ephemeral(&kem()).unwrap();
        let (s_bob, ct) = encapsulate(&kem(), &eph.encapsulation_key()).unwrap();
        let s_alice = decapsulate(&kem(), &eph, &ct).unwrap();
        assert_eq!(s_alice, s_bob);

        // Alice binds: pathless PQ commit injecting S, then a classical commit importing apq_psk.
        let attestation = ApqInfoUpdate {
            t_epoch: cl_epoch_before + 1,
            pq_epoch: pq_epoch_before + 1,
        };
        let (pq_commit, apq_psk) = inject_and_commit(
            asg.pq.as_mut().unwrap(),
            &s_alice,
            &[alice.pq().secret_store(), alice.classical().secret_store()],
            attestation,
        )
        .unwrap();
        let cl_out = apq_psk
            .add_to_commit(asg.classical.commit_builder())
            .unwrap()
            .build()
            .unwrap();
        asg.classical.apply_pending_commit().unwrap();
        let cl_commit = cl_out.commit_message.to_bytes().unwrap();

        // Bob applies the stapled commits.
        let (apq_psk_bob, bob_attestation) = apply_injected_commit(
            bob_recv.pq.as_mut().unwrap(),
            &s_bob,
            &pq_commit,
            &[bob.pq().secret_store(), bob.classical().secret_store()],
        )
        .unwrap();
        bob_recv
            .classical
            .process_incoming_message(MlsMessage::from_bytes(&cl_commit).unwrap())
            .unwrap();

        // Both PQ groups advanced by exactly one epoch (the pathless inject) and agree.
        assert_eq!(
            asg.pq.as_ref().unwrap().current_epoch(),
            pq_epoch_before + 1
        );
        assert_eq!(
            bob_recv.pq.as_ref().unwrap().current_epoch(),
            pq_epoch_before + 1
        );
        // Both classical groups advanced (the apq_psk bind) and agree.
        assert_eq!(asg.classical.current_epoch(), cl_epoch_before + 1);
        assert_eq!(bob_recv.classical.current_epoch(), cl_epoch_before + 1);
        // Both sides independently derived the same apq_psk (store key + value) from the
        // new PQ epoch.
        assert_eq!(apq_psk.storage_id(), apq_psk_bob.storage_id());
        assert_eq!(apq_psk.psk().raw_value(), apq_psk_bob.psk().raw_value());
        // The applied PQ commit surfaced the initiator's epoch attestation intact.
        assert_eq!(bob_attestation, attestation);

        // The classical group still works after the PQ-seeded epoch: Alice → Bob app message.
        let msg = asg
            .classical
            .encrypt_application_message(b"after-pq-ratchet", vec![])
            .unwrap();
        let decrypted = bob_recv
            .classical
            .process_incoming_message(MlsMessage::from_bytes(&msg.to_bytes().unwrap()).unwrap())
            .unwrap();
        let data = match decrypted {
            mls_rs::group::ReceivedMessage::ApplicationMessage(m) => m.data().to_vec(),
            _ => Vec::new(),
        };
        assert_eq!(data, b"after-pq-ratchet");
    }

    #[test]
    fn test_injected_secret_is_deleted_after_bind() {
        let alice = client();
        let bob = client();
        let (mut asg, welcome) = create_combiner_send_group(
            &bob.generate_classical_key_package().unwrap(),
            &bob.generate_pq_key_package().unwrap(),
            &alice,
            None,
        )
        .unwrap();
        let _bob_recv = join_combiner_group(&welcome, &bob).unwrap();

        let s_id = injected_psk_id(asg.pq.as_ref().unwrap());
        let eph = generate_ephemeral(&kem()).unwrap();
        let (_s_bob, ct) = encapsulate(&kem(), &eph.encapsulation_key()).unwrap();
        let s = decapsulate(&kem(), &eph, &ct).unwrap();
        let attestation = ApqInfoUpdate {
            t_epoch: asg.classical.current_epoch() + 1,
            pq_epoch: asg.pq.as_ref().unwrap().current_epoch() + 1,
        };
        inject_and_commit(
            asg.pq.as_mut().unwrap(),
            &s,
            &[alice.pq().secret_store(), alice.classical().secret_store()],
            attestation,
        )
        .unwrap();

        // Forward secrecy: the per-round ML-KEM secret is gone from the store after the bind.
        assert!(alice.pq().secret_store().get(&s_id).is_none());
    }

    /// Adversarial: the initiator commits a bind whose AppDataUpdate attests a WRONG
    /// pq_epoch (a value that is not the PQ half's next epoch). The responder's
    /// `TwoMlsRules::filter_proposals` runs on receive with the recv-PQ's pre-commit
    /// context and vetoes the commit — the epoch check is `attested == context.epoch + 1`
    /// — before any secret is folded. Proven by `apply_injected_commit` erroring.
    #[test]
    fn test_bind_with_wrong_epoch_attestation_is_vetoed_on_receive() {
        let alice = client();
        let bob = client();
        let (mut asg, welcome) = create_combiner_send_group(
            &bob.generate_classical_key_package().unwrap(),
            &bob.generate_pq_key_package().unwrap(),
            &alice,
            None,
        )
        .unwrap();
        let mut bob_recv = join_combiner_group(&welcome, &bob).unwrap();

        let eph = generate_ephemeral(&kem()).unwrap();
        let (s_bob, ct) = encapsulate(&kem(), &eph.encapsulation_key()).unwrap();
        let s_alice = decapsulate(&kem(), &eph, &ct).unwrap();

        // A lie: pq_epoch attests +2 instead of the true +1. Alice's OWN rules would
        // veto this on build too, so craft with a rogue-free path is unnecessary — the
        // point is the receiver's independent veto. (Alice's build also rejects it, so
        // this asserts inject_and_commit itself refuses to produce the poisoned commit.)
        let a_stores = [alice.pq().secret_store(), alice.classical().secret_store()];
        let bad = ApqInfoUpdate {
            t_epoch: asg.classical.current_epoch() + 1,
            pq_epoch: asg.pq.as_ref().unwrap().current_epoch() + 2,
        };
        assert!(
            inject_and_commit(asg.pq.as_mut().unwrap(), &s_alice, &a_stores, bad).is_err(),
            "the committer's own rules must veto a false epoch attestation at build"
        );

        // And a well-formed bind from a fresh round still applies on the responder — the
        // veto above did not corrupt either side's PQ group.
        let eph2 = generate_ephemeral(&kem()).unwrap();
        let (s_bob2, ct2) = encapsulate(&kem(), &eph2.encapsulation_key()).unwrap();
        let s_alice2 = decapsulate(&kem(), &eph2, &ct2).unwrap();
        let good = ApqInfoUpdate {
            t_epoch: asg.classical.current_epoch() + 1,
            pq_epoch: asg.pq.as_ref().unwrap().current_epoch() + 1,
        };
        let (pq_commit, _) =
            inject_and_commit(asg.pq.as_mut().unwrap(), &s_alice2, &a_stores, good).unwrap();
        let _ = (s_bob, s_bob2);
        let b_stores = [bob.pq().secret_store(), bob.classical().secret_store()];
        let (_, attestation) = apply_injected_commit(
            bob_recv.pq.as_mut().unwrap(),
            &s_alice2,
            &pq_commit,
            &b_stores,
        )
        .unwrap();
        assert_eq!(attestation, good);
    }

    #[test]
    fn test_tampered_ciphertext_yields_a_different_secret() {
        let eph = generate_ephemeral(&kem()).unwrap();
        let (s_bob, mut ct) = encapsulate(&kem(), &eph.encapsulation_key()).unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0xFF;
        // ML-KEM implicit rejection returns a pseudo-random secret, not an error.
        let s_alice = decapsulate(&kem(), &eph, &ct).unwrap();
        assert_ne!(
            s_alice, s_bob,
            "a tampered ciphertext must not recover the secret"
        );
    }
}
