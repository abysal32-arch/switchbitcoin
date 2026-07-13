//! Fuzz target for the wire parser (v3.16 Requirement 4).
//!
//! Setup (in a real environment):
//!   cargo install cargo-fuzz
//!   cargo fuzz run wire_parse       # run under libFuzzer + ASan
//!
//! Contract under test: `parse_message` AND the Task 05 envelope opener
//! `open_message` must be TOTAL — every input maps to Ok|Err, NEVER a panic.
//! `open_message` is the entry point actually facing a hostile peer (every
//! TCP frame passes through it inside `PeerSession`), so it gets the same
//! arbitrary bytes. libFuzzer treats any panic/abort/ASan finding as a
//! crash. This is exactly the class of bug that hit Bitcoin Core (Dec 2025):
//! deserializing MuSig2 pubkeys without validating they were on-curve points.

#![no_main]
use libfuzzer_sys::fuzz_target;
use swapkey::wire::{open_message, parse_message};

fuzz_target!(|data: &[u8]| {
    // We do NOT assert on Ok vs Err — any well-defined return is fine.
    // We ONLY require: no panic, no UB, no crash. Discard the results.
    let _ = parse_message(data);
    // Fixed expected sid: the sid-equality branch is a plain 32-byte compare,
    // so one expected value exercises every code path; taking the first 32
    // bytes as the sid instead would just shrink the fuzzed envelope space.
    let _ = open_message(&[0x5Au8; 32], data);
});
