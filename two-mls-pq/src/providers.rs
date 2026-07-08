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

/// The APQ mode this crate runs (confidentiality-only; see `apq::ApqMode`).
pub(crate) const APQ_MODE: apq::ApqMode = apq::ApqMode::ConfidentialityOnly;

/// The PQ half's cipher suite under [`APQ_MODE`].
pub(crate) fn pq_cipher_suite() -> mls_rs::CipherSuite {
    APQ_MODE.pq_cipher_suite()
}

/// The provider bundle handed to every `apq::CombinerClient` construction.
pub(crate) fn crypto_config() -> apq::CryptoConfig<Classical, Pq> {
    apq::CryptoConfig {
        classical: classical(),
        pq: pq(),
        mode: APQ_MODE,
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
