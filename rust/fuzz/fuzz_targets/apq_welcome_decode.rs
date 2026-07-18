#![no_main]

use libfuzzer_sys::fuzz_target;

// The APQ welcome is attacker-supplied and parsed before any MLS authentication runs, so its
// decoder is the highest-value parser to fuzz. The contract under test: on arbitrary input the
// decoder must only ever return `Ok(..)` or `Err(..)` — never panic, slice out of bounds, overflow
// a length, or hang.
fuzz_target!(|data: &[u8]| {
    let _ = apq::decode_apq_welcome(data);
});
