//! Concrete crypto-provider selection — the ONLY place this crate names a provider.
//!
//! `apq` is provider-agnostic; this module pins the classical and PQ `CryptoProvider`
//! types (and the PQ ratchet's KEM) per build feature, and everything else in the crate
//! compiles against the aliases. Exactly one provider family backs a build:
//!
//!   * `cryptokit` — Apple CryptoKit (macOS/iOS): `CryptoKitProvider` classical,
//!     `CryptoKitMlKemProvider` PQ. The shipped configuration.
//!   * `awslc` — aws-lc (portable): one `AwsLcCryptoProvider` serves both halves.
//!     Backs CI on Linux and cross-provider interop tests.
//!
//! When both are enabled (`--all-features` on an Apple dev machine), CryptoKit wins.

#[cfg(all(
    feature = "cryptokit",
    not(any(target_os = "macos", target_os = "ios"))
))]
compile_error!("the `cryptokit` feature requires a macOS or iOS target");

#[cfg(not(any(feature = "cryptokit", feature = "awslc")))]
compile_error!(
    "select a crypto provider feature: `cryptokit` (Apple targets) or `awslc` (portable)"
);

use crate::{Result, TwoMlsPqError};

#[cfg(feature = "cryptokit")]
mod selected {
    pub(crate) type Classical = mls_rs_crypto_cryptokit::CryptoKitProvider;
    pub(crate) type Pq = mls_rs_crypto_cryptokit::CryptoKitMlKemProvider;
    // ML-KEM-768 BY TYPE — unlike the awslc branch, this cannot follow the declared
    // suite's `hpke` facet at runtime. `tests::pq_kem_type_pin_matches_declared_suite`
    // is the tripwire: a new `TwoMlsSuite` variant with a different PQ KEM must update
    // this alias by hand.
    pub(crate) type PqKem = mls_rs_crypto_cryptokit::ml_kem::MlKem768Kem;

    pub(crate) fn classical() -> Classical {
        Classical::default()
    }
    pub(crate) fn pq() -> Pq {
        mls_rs_crypto_cryptokit::CryptoKitMlKemProvider
    }
    pub(crate) fn pq_kem() -> super::Result<PqKem> {
        Ok(PqKem::new())
    }
}

#[cfg(all(feature = "awslc", not(feature = "cryptokit")))]
mod selected {
    pub(crate) type Classical = mls_rs_crypto_awslc::AwsLcCryptoProvider;
    pub(crate) type Pq = mls_rs_crypto_awslc::AwsLcCryptoProvider;
    pub(crate) type PqKem = mls_rs_crypto_awslc::MlKemKem;

    pub(crate) fn classical() -> Classical {
        Classical::new()
    }
    pub(crate) fn pq() -> Pq {
        Pq::new()
    }
    pub(crate) fn pq_kem() -> super::Result<PqKem> {
        PqKem::new(super::pq_cipher_suite()).ok_or(super::TwoMlsPqError::Mls)
    }
}

// With neither feature the compile_error above fires; the unresolved `selected` errors
// that follow it are noise — the compile_error message is the diagnosis.
pub(crate) use selected::{classical, pq, pq_kem, Classical, Pq};

/// The cipher-suite pair this crate pins for every session — the `pair` facet of the
/// declared suite (`TwoMlsSuite::CURRENT`), which is the single source for every
/// suite-derived choice: this pair, the envelope HPKE, the header AEAD, and the digest.
/// Currently Curve25519/ChaCha classical + ML-KEM-768 PQ (confidentiality-only); the APQ
/// mode is derived from it (`ApqCipherSuite::mode`). Its coherence is enforced by the
/// `suite.validate()?` guard at every `CombinerClient` construction and asserted in tests.
///
/// `CipherSuite::ML_KEM_768` is the named constant `apq` unlocks via `mls-rs-core/post-quantum`;
/// it reaches us here through Cargo feature unification (`apq` is a required dependency, so the
/// feature is always on). The pinned wire value is asserted against it in `apq::client`.
pub(crate) const APQ_SUITE: apq::ApqCipherSuite = crate::suite::TwoMlsSuite::CURRENT.pair();

/// The PQ half's cipher suite — the declared suite's `hpke` facet (= `APQ_SUITE.pq`).
pub(crate) fn pq_cipher_suite() -> mls_rs::CipherSuite {
    crate::suite::TwoMlsSuite::CURRENT.hpke()
}

/// The provider bundle handed to every `apq::CombinerClient` construction.
pub(crate) fn crypto_config() -> apq::CryptoConfig<Classical, Pq> {
    apq::CryptoConfig {
        classical: classical(),
        pq: pq(),
        suite: APQ_SUITE,
    }
}

/// The suite provider backing the initial-envelope HPKE seal/open (spec A.1: sealed to
/// the PQ EK in KP') — the `hpke` facet of the declared suite (the PQ half), served by
/// the pinned PQ provider.
pub(crate) fn pq_envelope_suite(
) -> Result<impl mls_rs::CipherSuiteProvider<Error = impl std::error::Error + Send + Sync + 'static>>
{
    use mls_rs::CryptoProvider;
    pq().cipher_suite_provider(pq_cipher_suite())
        .ok_or(TwoMlsPqError::Mls)
}

/// The suite provider backing the header-encryption AEAD — the `header_aead` facet of
/// the declared suite (`TwoMlsSuite::CURRENT.header_aead()`, the classical half).
/// **Only the suite's AEAD and CSPRNG are used**
/// (`aead_seal`/`aead_open`/`random_bytes`/`aead_key_size`/`aead_nonce_size`); its
/// KEM/hash/signature are irrelevant. The header seal is still its own *layer* (versioned
/// by the `…headerKey.v1` exporter label, keys derived from either group half), but its
/// cipher is no longer an independent knob: it is a facet of the one declared suite —
/// changing it means declaring a new `TwoMlsSuite` variant, and both parties must run the
/// same declaration to open each other's frames. The header key length and nonce length
/// are read from the chosen suite (`header_aead_suite().aead_key_size()` /
/// `.aead_nonce_size()`), so nothing downstream assumes a specific cipher or size.
///
/// Both provider backends (awslc, cryptokit) must support the facet's suite. Why the
/// CLASSICAL half's AEAD seals the PQ side-band too: ChaCha20-Poly1305 (`0x0003`) has a
/// 256-bit key — the strongest AEAD margin, and notably better post-quantum headroom than
/// the PQ suite's AES-128-GCM.
pub(crate) fn header_aead_suite(
) -> Result<impl mls_rs::CipherSuiteProvider<Error = impl std::error::Error + Send + Sync + 'static>>
{
    use mls_rs::CryptoProvider;
    // The AEAD is a classical symmetric primitive; the classical provider supplies it.
    classical()
        .cipher_suite_provider(crate::suite::TwoMlsSuite::CURRENT.header_aead())
        .ok_or(TwoMlsPqError::Mls)
}

#[cfg(test)]
mod tests {
    /// Tripwire for the cryptokit backend's compile-time KEM pin: its `selected::PqKem`
    /// is ML-KEM-768 BY TYPE (`MlKem768Kem`), not derived from the declared suite the way
    /// the awslc branch's `MlKemKem::new(pq_cipher_suite())` is. If this fires, a new
    /// `TwoMlsSuite` variant changed the `hpke` facet — update the cryptokit `PqKem`
    /// alias to match, or the two backends silently run different A.4 ratchet KEMs.
    #[test]
    fn pq_kem_type_pin_matches_declared_suite() {
        assert_eq!(
            crate::suite::TwoMlsSuite::CURRENT.hpke(),
            mls_rs::CipherSuite::ML_KEM_768,
        );
    }
}
