//! Germ PQ ratchet (architecture-diagrams PR #2, §A.3): fresh ML-KEM entropy is injected into
//! the PQ group via a *pathless* PSK commit, then re-exported into the classical group, so the
//! whole bind is cheap and staple-able to an app message — no per-round PQ updatePath.
//!
//! The initiator sends an encapsulation key (EK), the responder encapsulates a fresh shared
//! secret S and returns the ciphertext, and the initiator decapsulates. Both sides then inject S
//! as a PSK into the PQ group (a commit with no updatePath) and re-export the `apq_psk` from the
//! resulting epoch to bind into the classical group.
//!
//! Needs real ML-KEM, so the whole module is `cryptokit`-only.

use mls_rs::crypto::{HpkePublicKey, HpkeSecretKey};
use mls_rs::psk::{ExternalPskId, PreSharedKey};
use mls_rs::{CipherSuite, MlsMessage};
use mls_rs_crypto_awslc::MlKemKem;
use mls_rs_crypto_traits::KemType;
use zeroize::Zeroizing;

use crate::client::CombinerClient;
use crate::group::{export_and_register_psk_pq, injected_secret_psk_id, PqMlsGroup};
use crate::{CombinerError, Result};

const ML_KEM_768: u16 = 0xFDEA;

fn ml_kem() -> Result<MlKemKem> {
    MlKemKem::new(CipherSuite::from(ML_KEM_768)).ok_or(CombinerError::Mls)
}

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
}

/// Initiator step 1 — generate a fresh ML-KEM-768 keypair.
pub fn generate_ephemeral() -> Result<PqEphemeral> {
    let (dk, ek) = ml_kem()?.generate().map_err(|_| CombinerError::Mls)?;
    Ok(PqEphemeral { dk, ek })
}

/// Responder — encapsulate to the initiator's EK, returning `(shared_secret S, ciphertext ct)`.
/// `S` is wrapped in `Zeroizing` so it is wiped from memory on drop.
pub fn encapsulate(ek_bytes: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    let ek = HpkePublicKey::from(ek_bytes.to_vec());
    let res = ml_kem()?.encap(&ek).map_err(|_| CombinerError::Mls)?;
    Ok((Zeroizing::new(res.shared_secret.to_vec()), res.enc.to_vec()))
}

/// Initiator step 2 — decapsulate the responder's `ct` with the held DK, recovering S (zeroizing).
pub fn decapsulate(eph: &PqEphemeral, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let s = ml_kem()?
        .decap(ct, &eph.dk, &eph.ek)
        .map_err(|_| CombinerError::Mls)?;
    Ok(Zeroizing::new(s))
}

/// PSK id for the injected secret S at the PQ group's current epoch. The trailing domain byte
/// (see `group::PSK_DOMAIN_INJECTED`) keeps it disjoint from any exported `apq_psk` id, which is
/// derived from the *next* epoch and carries no domain byte.
fn injected_psk_id(group: &PqMlsGroup) -> ExternalPskId {
    injected_secret_psk_id(group.current_epoch(), group.group_id())
}

/// Holds an injected secret S registered in the PQ secret store and removes it on drop, so the
/// per-round ML-KEM entropy is cleared on **every** exit path — including early `?` returns — not
/// just the happy path. This is what gives the ratchet forward secrecy: a later state compromise
/// cannot recover S. `id` is reused for the commit's `add_external_psk` proposal.
struct InjectedSecret<'a> {
    id: ExternalPskId,
    client: &'a CombinerClient,
}

impl<'a> InjectedSecret<'a> {
    fn register(group: &PqMlsGroup, s: &[u8], client: &'a CombinerClient) -> Self {
        let id = injected_psk_id(group);
        let mut pq = client.pq().secret_store();
        pq.insert(id.clone(), PreSharedKey::new(s.to_vec()));
        Self { id, client }
    }
}

impl Drop for InjectedSecret<'_> {
    fn drop(&mut self) {
        let mut pq = self.client.pq().secret_store();
        pq.delete(&self.id);
    }
}

/// Initiator (committer) — inject S into `pq_group` via a pathless PSK commit, apply it, and
/// re-export the `apq_psk` from the new PQ epoch (registered for the classical bind).
/// Returns `(pq_commit_bytes, apq_psk_id)`.
pub fn inject_and_commit(
    pq_group: &mut PqMlsGroup,
    s: &[u8],
    client: &CombinerClient,
) -> Result<(Vec<u8>, ExternalPskId)> {
    let secret = InjectedSecret::register(pq_group, s, client);
    let out = pq_group
        .commit_builder()
        .add_external_psk(secret.id.clone())
        .map_err(|_| CombinerError::Mls)?
        .build()
        .map_err(|_| CombinerError::Mls)?;
    pq_group
        .apply_pending_commit()
        .map_err(|_| CombinerError::Mls)?;
    // S is now folded into the new epoch; wipe it from the store before re-exporting.
    drop(secret);
    let apq_psk_id = export_and_register_psk_pq(pq_group, client)?;
    let bytes = out
        .commit_message
        .to_bytes()
        .map_err(|_| CombinerError::Mls)?;
    Ok((bytes, apq_psk_id))
}

/// Responder (applier) — register S (held since `encapsulate`), apply the initiator's pathless PQ
/// commit, and re-export the same `apq_psk` from the new PQ epoch.
pub fn apply_injected_commit(
    pq_group: &mut PqMlsGroup,
    s: &[u8],
    pq_commit: &[u8],
    client: &CombinerClient,
) -> Result<ExternalPskId> {
    let secret = InjectedSecret::register(pq_group, s, client);
    let msg = MlsMessage::from_bytes(pq_commit).map_err(|_| CombinerError::Mls)?;
    pq_group
        .process_incoming_message(msg)
        .map_err(|_| CombinerError::Mls)?;
    // S is now folded into the new epoch; wipe it before re-exporting.
    drop(secret);
    export_and_register_psk_pq(pq_group, client)
}

/// Benchmark fixture (never enabled in production): the "old" APQ-faithful per-round PQ cost — a
/// self-Update commit on an ML-KEM-768 group carrying a full updatePath (leaf + path keys +
/// ciphertext), for comparison against the pathless PSK-injection commit. Uses a path-required
/// client to force the updatePath.
#[cfg(feature = "benchmark_util")]
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub fn full_pq_updatepath_commit_size() -> usize {
    use mls_rs::client_builder::ClientBuilder;
    use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
    use mls_rs::identity::SigningIdentity;
    use mls_rs::mls_rules::{CommitOptions, DefaultMlsRules};
    use mls_rs::{CipherSuiteProvider, CryptoProvider, ExtensionList};
    use mls_rs_crypto_awslc::AwsLcCryptoProvider;

    let suite = CipherSuite::from(ML_KEM_768);
    let rules =
        DefaultMlsRules::new().with_commit_options(CommitOptions::new().with_path_required(true));
    let build = |rules: DefaultMlsRules| {
        let cs = AwsLcCryptoProvider::new()
            .cipher_suite_provider(suite)
            .unwrap();
        let (sk, pk) = cs.signature_key_generate().unwrap();
        let signing = SigningIdentity::new(
            BasicCredential::new(pk.as_ref().to_vec()).into_credential(),
            pk,
        );
        ClientBuilder::new()
            .crypto_provider(AwsLcCryptoProvider::new())
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
    use crate::CombinerClient;
    use mls_rs::{CipherSuiteProvider, CryptoProvider};
    use mls_rs_crypto_rustcrypto::RustCryptoProvider;

    fn client() -> CombinerClient {
        let crypto = RustCryptoProvider::new();
        let cs = crypto
            .cipher_suite_provider(mls_rs::CipherSuite::CURVE25519_CHACHA)
            .unwrap();
        let (secret, _) = cs.signature_key_generate().unwrap();
        CombinerClient::new(secret.as_bytes().to_vec()).unwrap()
    }

    #[test]
    fn test_kem_encapsulate_decapsulate_round_trips() {
        let eph = generate_ephemeral().unwrap();
        let ek = eph.encapsulation_key();
        assert_eq!(ek.len(), 1184, "ML-KEM-768 EK is 1184 bytes");

        let (s_bob, ct) = encapsulate(&ek).unwrap();
        assert_eq!(ct.len(), 1088, "ML-KEM-768 ciphertext is 1088 bytes");
        assert_eq!(s_bob.len(), 32, "ML-KEM-768 shared secret is 32 bytes");

        let s_alice = decapsulate(&eph, &ct).unwrap();
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
        )
        .unwrap();
        let mut bob_recv = join_combiner_group(&welcome, &bob).unwrap();

        let pq_epoch_before = asg.pq.current_epoch();
        let cl_epoch_before = asg.classical.current_epoch();

        // EK/ct exchange: Alice initiates, Bob responds, Alice recovers S.
        let eph = generate_ephemeral().unwrap();
        let (s_bob, ct) = encapsulate(&eph.encapsulation_key()).unwrap();
        let s_alice = decapsulate(&eph, &ct).unwrap();
        assert_eq!(s_alice, s_bob);

        // Alice binds: pathless PQ commit injecting S, then a classical commit importing apq_psk.
        let (pq_commit, apq_psk_id) = inject_and_commit(&mut asg.pq, &s_alice, &alice).unwrap();
        let cl_out = asg
            .classical
            .commit_builder()
            .add_external_psk(apq_psk_id.clone())
            .unwrap()
            .build()
            .unwrap();
        asg.classical.apply_pending_commit().unwrap();
        let cl_commit = cl_out.commit_message.to_bytes().unwrap();

        // Bob applies the stapled commits.
        let apq_psk_id_bob =
            apply_injected_commit(&mut bob_recv.pq, &s_bob, &pq_commit, &bob).unwrap();
        bob_recv
            .classical
            .process_incoming_message(MlsMessage::from_bytes(&cl_commit).unwrap())
            .unwrap();

        // Both PQ groups advanced by exactly one epoch (the pathless inject) and agree.
        assert_eq!(asg.pq.current_epoch(), pq_epoch_before + 1);
        assert_eq!(bob_recv.pq.current_epoch(), pq_epoch_before + 1);
        // Both classical groups advanced (the apq_psk bind) and agree.
        assert_eq!(asg.classical.current_epoch(), cl_epoch_before + 1);
        assert_eq!(bob_recv.classical.current_epoch(), cl_epoch_before + 1);
        // Both sides independently derived the same apq_psk id from the new PQ epoch.
        let alice_apq: &[u8] = &apq_psk_id;
        let bob_apq: &[u8] = &apq_psk_id_bob;
        assert_eq!(alice_apq, bob_apq);

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
        )
        .unwrap();
        let _bob_recv = join_combiner_group(&welcome, &bob).unwrap();

        let s_id = injected_psk_id(&asg.pq);
        let eph = generate_ephemeral().unwrap();
        let (_s_bob, ct) = encapsulate(&eph.encapsulation_key()).unwrap();
        let s = decapsulate(&eph, &ct).unwrap();
        inject_and_commit(&mut asg.pq, &s, &alice).unwrap();

        // Forward secrecy: the per-round ML-KEM secret is gone from the store after the bind.
        assert!(alice.pq().secret_store().get(&s_id).is_none());
    }

    #[test]
    fn test_tampered_ciphertext_yields_a_different_secret() {
        let eph = generate_ephemeral().unwrap();
        let (s_bob, mut ct) = encapsulate(&eph.encapsulation_key()).unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0xFF;
        // ML-KEM implicit rejection returns a pseudo-random secret, not an error.
        let s_alice = decapsulate(&eph, &ct).unwrap();
        assert_ne!(
            s_alice, s_bob,
            "a tampered ciphertext must not recover the secret"
        );
    }
}
