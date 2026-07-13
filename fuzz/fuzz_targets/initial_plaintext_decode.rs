#![no_main]

use libfuzzer_sys::fuzz_target;

// The §A.1 envelope plaintext (v15) is attacker-influenced before any MLS
// authentication runs: the envelope seals to a PUBLIC key, so anyone can compose one,
// and `decode_initial_plaintext` parses the four optional sections straight off the
// HPKE-opened bytes. Same contract as the other attacker-facing decoders: on arbitrary
// input, only ever `Ok(..)` or `Err(..)` — never panic, slice out of bounds, overflow
// a length, or hang. (The sections it yields feed the welcome/KP/MLS parsers, each a
// fuzzed surface of its own.)
fuzz_target!(|data: &[u8]| {
    let _ = two_mls_pq::key_packages::decode_initial_plaintext(data.to_vec());
});
