//! Fuzz target for the wire parser (v3.16 Requirement 4).
//!
//! Setup (in a real environment):
//!   cargo install cargo-fuzz
//!   cargo fuzz run wire_parse       # run under libFuzzer + ASan
//!
//! Contract under test: `parse_message` must be TOTAL — every input maps to
//! Ok|Err, NEVER a panic. libFuzzer treats any panic/abort/ASan finding as a
//! crash. This is exactly the class of bug that hit Bitcoin Core (Dec 2025):
//! deserializing MuSig2 pubkeys without validating they were on-curve points.

#![no_main]
use libfuzzer_sys::fuzz_target;
use newkey::wire::parse_message;

fuzz_target!(|data: &[u8]| {
    // We do NOT assert on Ok vs Err — any well-defined return is fine.
    // We ONLY require: no panic, no UB, no crash. Discard the result.
    let _ = parse_message(data);
});
