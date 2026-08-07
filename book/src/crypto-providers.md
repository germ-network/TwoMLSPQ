# Crypto Providers

[Cipher Suites & Feature Flags](./cipher-suites.md) covers *how* to select a provider. This
chapter records *why* there are two, what each can actually do, and which alternatives are
foreclosed — so the recurring questions ("can we use one provider?", "can Android use the
platform's BoringSSL?") have a written answer.

Verified against `germ-network/TwoMLSPQ` `main` @ `3c25a8a` and the pinned `mls-rs` fork rev
`b43703f`, with `aws-lc-sys 0.40.0`, NDK r27d, and the Swift 6.3.3 SDK for Android.

## What exists, and what actually implements 0xFDEA

`mls-rs` ships seven crypto crates. Six register a `CryptoProvider`. **Only two implement
0xFDEA with real ML-KEM-768.** The distinction matters: a provider that compiles is not a
provider that works. Through the 0.0.x tags the default feature set had no ML-KEM at all —
`PqMlsGroup` aliased to the classical group, so the "PQ half" was a second X25519 group and
`generate_combiner_key_package()` failed. That is why the crate now has **no default provider
feature** and a `compile_error!` instead.

| Crate | Registers | 0xFDEA with real ML-KEM-768 | Links |
|---|---|---|---|
| `mls-rs-crypto-awslc` | 1, 2, 3, 5, 7 — plus 65001/**65002**/65003/65100 under `post-quantum` | **Yes.** `aws_lc_rs::kem::ML_KEM_768`, with `EVP_PKEY_decapsulate` and `EVP_PKEY_keygen_deterministic`. Secret key 2400 B | Vendored AWS-LC C (a BoringSSL derivative) |
| `mls-rs-crypto-cryptokit` | 1, 2, 3, 5, 7 classical — 65002 only in the PQ provider | **Yes.** CryptoKit `MLKEM768`. Secret key 96 B | Static Swift archive against the OS CryptoKit framework |
| `mls-rs-crypto-openssl` | 1–7 | No | System OpenSSL |
| `mls-rs-crypto-rustcrypto` | 1, 2, 3, 7 | No | Pure Rust |
| `mls-rs-crypto-webcrypto` | 2, 5, 7 | No | Browser SubtleCrypto |
| `mls-rs-crypto-hpke` | — | n/a — the RFC 9180 engine both PQ providers instantiate | Pure Rust |
| `mls-rs-crypto-traits` | — | n/a — its `KemId` holds only the five RFC 9180 DHKEMs, which is why both PQ providers hardcode `kem_id()` | Pure Rust |

Two things worth knowing about the non-PQ providers: they do not silently degrade. Asking any
of them for 0xFDEA routes through `KemId::new`, which returns `None`, so the suite is simply
unavailable. And `mls-rs-crypto-hpke`'s X-Wing combiner serves suite **65100**, not 0xFDEA —
0xFDEA is *pure* ML-KEM-768, where Ed25519 is the signature scheme rather than a KEM half.

## Android cannot use the platform's BoringSSL

Android ships BoringSSL and AWS-LC is a BoringSSL fork, so the question comes up. The answer is
no, and it is not a close call.

The NDK sysroot contains **no `libcrypto` or `libssl` link stub** for any ABI at any API level —
there is nothing to pass to `-lcrypto`. On a device the library exists at
`/system/lib64/libcrypto.so` but is absent from `/system/etc/public.libraries.txt`, so the
dynamic linker refuses it to app code. Google closed this in Android 7.0, finished it in 8.0,
and hardened it again in 12. Their documented remedy is to bundle your own.

Conscrypt is not a way around it: it is a JCA/JSSE provider with no C ABI, and its own AAR
ships a bundled BoringSSL — vendoring, performed by Google. Android Keystore is not either.
Of the five primitives 0xFDEA needs — ML-KEM-768, Ed25519, HKDF-SHA256, AES-128-GCM, HPKE — it
exposes one, and non-exportably. That is disqualifying on its own: MLS needs raw path and epoch
secrets in process, and Keystore's guarantee is precisely that key material never gets there.

So Android vendors AWS-LC. Measured cost, release profile, stripped: **2,959,368 B** for
arm64-v8a and **4,117,976 B** for x86_64, linking only `libdl` and `libc`.

## Why not one provider everywhere

Running `awslc` on Apple too would remove a provider, retire the `provider_interop` suite's
load-bearing role, and make one binary serve both platforms. It is **foreclosed on size.**

The iOS device dylib built with `cryptokit` is **1,302,308 B**. The same crate built with
`awslc` for Android arm64 — same `opt-level="z"`, `lto="fat"`, `panic="abort"` profile — is
**2,959,368 B**. The roughly **1.65 MB** difference is what vendoring AWS-LC costs instead of
linking the OS framework. (Cross-OS, so treat it as an indicative figure rather than an exact
iOS delta.) The App Clip budget has about **1.28 MB** of headroom against Apple's ceiling and a
**500 KB** CI ratchet margin. It does not fit.

Nothing else pushes back the other way. CryptoKit and the Swift runtime are OS dylibs costing
zero bundle bytes, and the static Swift bridge contributes about 600 B of metadata — so
dropping `cryptokit` would return almost nothing. No compliance requirement binds either: every
"FIPS" reference in this codebase is FIPS 203, the ML-KEM standard, never FIPS 140/CMVP, and
aws-lc-rs documents its FIPS mode as unsupported on iOS. The iOS-version argument is also moot —
the consuming app already floors at iOS 26, so CryptoKit's ML-KEM availability costs nothing.

## Archive portability is a serialisation choice, not a barrier

The providers store ML-KEM secret keys differently — CryptoKit 96 bytes, AWS-LC 2400 bytes —
and those bytes reach the session archive through the group snapshot's `TreeKemPrivate`. It is
tempting to conclude that a session archived on one platform can never be restored on the
other. **That conclusion is wrong, and it should not be repeated.**

Both providers hold the same key. They disagree only about how to write it down, and the ML-KEM
private-key encoding is exactly the thing that is not yet standardised — neither 96 nor 2400 is
*the* format. CryptoKit's 96 bytes are the 64-byte FIPS 203 seed `d || z` plus an integrity
check; AWS-LC's 2400 are the expanded decapsulation key, derivable from that seed.

The seed is the common denominator, and **both providers already speak it in both directions**:
CryptoKit exposes `seedRepresentation` as a readable property and accepts it in an initializer,
while AWS-LC's `generate()` picks 64 random bytes itself before calling
`generate_deterministic`, then discards them. This is also why the two providers derive
byte-identical key pairs from the same `dkp_prk`, which `provider_interop` already proves.

Portable archives therefore need a provider change — persist the seed rather than the native
handle — not a provider *removal*. Two things gate it: an unmeasured keygen-per-decap cost on
the AWS-LC side, and a safety fix. AWS-LC's `decap()` passes a hardcoded 2400 to
`EVP_PKEY_kem_new_raw_secret_key` without checking the supplied key's length, and the archive
header carries no key-format discriminator, so a mismatched key is an out-of-bounds read rather
than a clean error. **Any change to the stored encoding must land the length check and the
discriminator first, so it fails closed.**
