//! The TwoMLS suite — ONE up-front declaration that every downstream crypto
//! choice reads from.
//!
//! A session's cryptography is not a set of independent knobs: the group pair,
//! the §A.1/A.3 envelope HPKE, the header-encryption AEAD, and the protocol
//! digest are facets of a single named configuration, declared here as
//! [`TwoMlsSuite`] and pinned for the build as [`TwoMlsSuite::CURRENT`]. The
//! facets:
//!
//!   * **pair** — the classical + PQ MLS cipher suites the two group halves run
//!     (`crypto_config`, and the wire suite id the invitation/session archives
//!     and the `APQInfo` extension carry).
//!   * **hpke** — the suite backing the §A.1 establishment envelope and the
//!     parallel A.3 bootstrap-KP envelope: the **PQ half** (the envelope is
//!     sealed to the PQ EK in the published KP′).
//!   * **header AEAD** — the outer seal on every rendezvous-channel frame and
//!     the A.4 injected-secret seal: the **classical half's AEAD**
//!     (ChaCha20-Poly1305 — its 256-bit key has the strongest post-quantum
//!     margin, notably better than the PQ suite's AES-128-GCM, which is why the
//!     PQ side-band too is sealed with it).
//!   * **digest** — the hash behind every digest the crate emits (session ids,
//!     welcome digests, proposal/app AAD, the A.3 bootstrap-KP commitment): the
//!     **classical half's hash** (SHA-256), one coherent classical family.
//!
//! The enum's public life starts at the key-package posting: each half of a
//! published `APQKeyPackage` names its cipher suite in the KeyPackage's
//! cleartext framing, so the pair is publicly readable off the posted KP, and
//! the suite of every inbound §A.1 ciphertext is thereafter *defined* by which
//! posted KP (→ which invitation) it was sealed to — the receiver holds a
//! limited, known key set and never guesses. The §A.1 HPKE seal additionally
//! *binds* the declared suite via untransmitted AAD (see [`framing_aad`]).
//!
//! This is agility readiness, not negotiation: exactly one variant exists, and
//! every decoder validates a carried suite `== CURRENT`. Widening the accepted
//! set (a `suite → provider` registry, per-invitation suites) is the separate,
//! deferred protocol change; declaring the suite once, encoding it once, and
//! binding it everywhere is that change's groundwork.

use apq::ApqCipherSuite;
use mls_rs::CipherSuite;

/// The named suites TwoMLS can run. One variant today; a future suite is a new
/// variant, not a new constant — every facet accessor is `match`-exhaustive, so
/// adding one forces each derived decision to be made explicitly. (Deliberately
/// NOT `#[non_exhaustive]`: the attribute would be inert on a crate-private type,
/// and the exhaustive in-crate matching is the whole forcing-function.)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum TwoMlsSuite {
    /// Curve25519/ChaCha classical · ML-KEM-768 PQ · ChaCha20-Poly1305 header
    /// AEAD · SHA-256 digest.
    Curve25519ChaChaMlKem768,
}

impl TwoMlsSuite {
    /// The build-pinned suite: the single configuration every session runs.
    pub(crate) const CURRENT: Self = Self::Curve25519ChaChaMlKem768;

    /// The classical + PQ MLS cipher-suite pair the group halves run — the
    /// source of `providers::APQ_SUITE` and of the wire suite id.
    pub(crate) const fn pair(self) -> ApqCipherSuite {
        match self {
            Self::Curve25519ChaChaMlKem768 => ApqCipherSuite {
                classical: CipherSuite::CURVE25519_CHACHA,
                pq: CipherSuite::ML_KEM_768,
            },
        }
    }

    /// The suite backing the §A.1/A.3 envelope HPKE: the PQ half (the envelope
    /// is sealed to the PQ EK in the published KP′).
    pub(crate) const fn hpke(self) -> CipherSuite {
        self.pair().pq
    }

    /// The suite whose AEAD seals every rendezvous-channel frame (and the A.4
    /// injected secret): the classical half. See the module doc for why the
    /// classical AEAD covers the PQ side-band too.
    pub(crate) const fn header_aead(self) -> CipherSuite {
        self.pair().classical
    }

    /// The digest behind every hash this crate emits — the classical half's
    /// hash family, dispatched infallibly per variant (no provider round-trip:
    /// digests key replay ledgers and AAD, so they must not be able to fail).
    pub(crate) fn digest(self, bytes: &[u8]) -> Vec<u8> {
        match self {
            Self::Curve25519ChaChaMlKem768 => {
                use sha2::{Digest, Sha256};
                Sha256::digest(bytes).to_vec()
            }
        }
    }

    /// The suite's wire identity — the `apq` pair codec (classical u16 BE ‖ pq
    /// u16 BE), the SAME bytes the invitation/session archive headers carry.
    /// One encoding for one suite; do not invent a second.
    pub(crate) fn to_wire(self) -> [u8; 4] {
        self.pair().to_wire()
    }

    /// Inverse of [`to_wire`], admitting only recognized variants: a pair that
    /// is not a declared `TwoMlsSuite` is `None`, never a partially-supported
    /// suite. (Single-variant today, so this is exactly the `== CURRENT` guard
    /// the archive decoders apply.)
    pub(crate) fn from_wire(bytes: [u8; 4]) -> Option<Self> {
        (ApqCipherSuite::from_wire(bytes) == Self::CURRENT.pair()).then_some(Self::CURRENT)
    }
}

/// Version byte of the §A.1 envelope's AAD framing — bumping it is a deliberate
/// compatibility cut (older builds fail the AEAD tag, `DecryptionFailed`).
pub(crate) const ENVELOPE_FRAMING_VERSION: u8 = 1;

/// The §A.1 envelope's HPKE AAD: `[ENVELOPE_FRAMING_VERSION][suite.to_wire()]`,
/// **derived locally on both sides and never transmitted** (RFC 9180 `aad` is a
/// seal/open input, not part of the ciphertext — only byte-equality matters).
/// The seal side derives it from the build's declared suite; the open side from
/// its own build/invitation. A peer whose declared pair (or framing version)
/// differs fails the AEAD tag → `DecryptionFailed` — deliberately opaque, the
/// same "indistinguishable by construction" contract as the header seal's
/// `try_open`. This binds the CLASSICAL half too (which the HPKE operation
/// alone never touches): downgrade binding at zero wire and zero plaintext
/// bytes. The crisp `CipherSuiteMismatch` errors stay where the suite is
/// *readable* — KP validation, `APQInfo` at join, invitation/archive decode.
pub(crate) fn framing_aad(suite: TwoMlsSuite) -> [u8; 5] {
    let w = suite.to_wire();
    [ENVELOPE_FRAMING_VERSION, w[0], w[1], w[2], w[3]]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The facet invariant sweep: every derived decision equals the value the
    /// crate pinned before the enum existed, so introducing it is byte-for-byte
    /// behavior-preserving.
    #[test]
    fn facets_match_the_pinned_configuration() {
        let s = TwoMlsSuite::CURRENT;
        assert_eq!(s.pair().classical, CipherSuite::CURVE25519_CHACHA);
        assert_eq!(s.pair().pq, CipherSuite::ML_KEM_768);
        assert_eq!(s.hpke(), CipherSuite::ML_KEM_768);
        assert_eq!(s.header_aead(), CipherSuite::CURVE25519_CHACHA);
        assert!(s.pair().validate().is_ok());
    }

    #[test]
    fn digest_is_sha256() {
        use sha2::{Digest, Sha256};
        let bytes = b"twomls-suite-digest";
        assert_eq!(
            TwoMlsSuite::CURRENT.digest(bytes),
            Sha256::digest(bytes).to_vec()
        );
    }

    #[test]
    fn wire_round_trips_and_rejects_foreign_pairs() {
        let w = TwoMlsSuite::CURRENT.to_wire();
        assert_eq!(TwoMlsSuite::from_wire(w), Some(TwoMlsSuite::CURRENT));
        // A recognized-but-different pair (classical/classical) is not a variant.
        assert_eq!(TwoMlsSuite::from_wire([0x00, 0x01, 0x00, 0x03]), None);
        assert_eq!(TwoMlsSuite::from_wire([0xFF, 0xFF, 0xFF, 0xFF]), None);
    }

    #[test]
    fn framing_aad_is_version_then_pair() {
        let aad = framing_aad(TwoMlsSuite::CURRENT);
        assert_eq!(aad[0], ENVELOPE_FRAMING_VERSION);
        assert_eq!(&aad[1..], &TwoMlsSuite::CURRENT.to_wire());
    }
}
