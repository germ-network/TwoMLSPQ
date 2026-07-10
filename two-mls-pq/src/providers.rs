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

/// The cipher-suite pair this crate pins for every session: Curve25519/ChaCha classical +
/// ML-KEM-768 PQ (confidentiality-only). The APQ mode is derived from it (`ApqCipherSuite::mode`).
/// A struct literal (not the fallible `new`) so it is a `const`; its coherence is enforced by the
/// `suite.validate()?` guard at every `CombinerClient` construction and asserted in tests.
///
/// `CipherSuite::ML_KEM_768` is the named constant `apq` unlocks via `mls-rs-core/post-quantum`;
/// it reaches us here through Cargo feature unification (`apq` is a required dependency, so the
/// feature is always on). The pinned wire value is asserted against it in `apq::client`.
pub(crate) const APQ_SUITE: apq::ApqCipherSuite = apq::ApqCipherSuite {
    classical: mls_rs::CipherSuite::CURVE25519_CHACHA,
    pq: mls_rs::CipherSuite::ML_KEM_768,
};

/// The PQ half's cipher suite under [`APQ_SUITE`].
pub(crate) fn pq_cipher_suite() -> mls_rs::CipherSuite {
    APQ_SUITE.pq
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
/// the PQ EK in KP') — the PQ suite of the pinned provider.
pub(crate) fn pq_envelope_suite(
) -> Result<impl mls_rs::CipherSuiteProvider<Error = impl std::error::Error + Send + Sync + 'static>>
{
    use mls_rs::CryptoProvider;
    pq().cipher_suite_provider(pq_cipher_suite())
        .ok_or(TwoMlsPqError::Mls)
}

/// The suite provider backing the header-encryption AEAD (the outer symmetric seal over
/// every rendezvous-channel frame) — the classical suite of the pinned provider, so the
/// AEAD is ChaCha20-Poly1305 and the nonce/key sizes track the pinned suite.
pub(crate) fn classical_aead_suite(
) -> Result<impl mls_rs::CipherSuiteProvider<Error = impl std::error::Error + Send + Sync + 'static>>
{
    use mls_rs::CryptoProvider;
    classical()
        .cipher_suite_provider(APQ_SUITE.classical)
        .ok_or(TwoMlsPqError::Mls)
}
