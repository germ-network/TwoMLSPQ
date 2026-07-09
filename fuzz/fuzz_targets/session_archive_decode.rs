#![no_main]

use libfuzzer_sys::fuzz_target;
use two_mls_pq::{Archive, TwoMlsPqSession};

// A session archive is attacker-influencable at rest (a tampered backing store) and is
// parsed before anything in it can authenticate, so its decoder carries the same contract
// as the welcome decoder: on arbitrary input, only ever `Ok(..)` or `Err(..)` — never
// panic, slice out of bounds, overflow a length, or hang.
//
// Restore is self-contained (no client argument): the archive carries the signing
// identity, so the decoder rebuilds the client from arbitrary bytes too — that rebuild is
// on the fuzzed path.
fuzz_target!(|data: &[u8]| {
    let _ = TwoMlsPqSession::from_archive(Archive {
        bytes: data.to_vec(),
    });
});
