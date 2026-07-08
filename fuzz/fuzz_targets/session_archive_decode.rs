#![no_main]

use std::sync::{Arc, OnceLock};

use libfuzzer_sys::fuzz_target;
use two_mls_pq::key_packages::TwoMlsPqIdentity;
use two_mls_pq::{Archive, TwoMlsPqSession};

// A session archive is attacker-influencable at rest (a tampered backing store) and is
// parsed before anything in it can authenticate, so its decoder carries the same contract
// as the welcome decoder: on arbitrary input, only ever `Ok(..)` or `Err(..)` — never
// panic, slice out of bounds, overflow a length, or hang.
//
// The client is fixed across runs; its short id keeps the identity comparison solvable by
// coverage, letting the fuzzer reach the group-snapshot import path behind it.
fn client() -> Arc<TwoMlsPqIdentity> {
    static CLIENT: OnceLock<Arc<TwoMlsPqIdentity>> = OnceLock::new();
    Arc::clone(CLIENT.get_or_init(|| {
        TwoMlsPqIdentity::new(b"fz".to_vec()).expect("opaque ids construct infallibly")
    }))
}

fuzz_target!(|data: &[u8]| {
    let _ = TwoMlsPqSession::from_archive(
        Archive {
            bytes: data.to_vec(),
        },
        client(),
    );
});
