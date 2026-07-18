#![no_main]

use libfuzzer_sys::fuzz_target;

// The message frame (0x03) is the attacker-facing frame parser: every inbound
// message-path blob goes through `decode_message_frame` before any MLS processing, so
// it carries the same contract as the welcome and archive decoders — on arbitrary
// input, only ever `Ok(..)` or `Err(..)`; never panic, slice out of bounds, overflow a
// length, or hang. (The sections it yields feed `MlsMessage::from_bytes`, which is
// mls-rs's own fuzzed surface.)
fuzz_target!(|data: &[u8]| {
    two_mls_pq::session::fuzz_decode_message_frame(data);
});
