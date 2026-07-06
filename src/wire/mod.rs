//! Wire format + parser — the FUZZ TARGET (v3.16 Requirement 4) and the front
//! line of the validation gate (Requirement 2).
//!
//! HARD RULE: `parse_message` must NEVER panic on ANY input — only ever return
//! `Ok(Message)` (fully validated) or `Err`. Every field that is a point/scalar/
//! nonce/partial is parsed THROUGH the `crypto::validate` newtypes, so a parsed
//! `Message` is validated by construction. The fuzzer throws arbitrary bytes here.
//!
//! Do NOT use indexing (`b[i]`), `unwrap`, `expect`, slicing without length
//! checks, or `from_be_bytes` on unchecked slices. Use `get(..)?` and checked
//! conversions so malformed/truncated/oversized inputs return Err, not a panic.

use crate::crypto::{ValidatedPoint, ValidatedPubNonce, ValidatedPartial};
use crate::crypto::adaptor::AdaptorPoint;
use crate::{Error, Result};

/// The Phase-5 messages, in the exact order the possession gate requires.
/// (Discovery/matching messages are STUBBED out of this build — Requirement 5.)
#[derive(Debug)]
pub enum Message {
    /// (1) public nonces for BOTH completions (commit-then-reveal happens above this).
    Nonces { comp_sh: ValidatedPubNonce, comp_sl: ValidatedPubNonce },
    /// (2) SH publishes T = t*G.
    AdaptorPointMsg(AdaptorPoint),
    /// (3) SH's partials on BOTH completions.
    ShPartials { comp_sh: ValidatedPartial, comp_sl: ValidatedPartial },
    /// (5) SL's single enabling partial on Comp->SH.
    SlEnablingPartial(ValidatedPartial),
    /// Fresh destination pubkey exchange (Phase 5 step 12).
    Destination(ValidatedPoint),
}

/// THE fuzz entry point. Must be total: every byte string maps to Ok|Err, never panic.
pub fn parse_message(_bytes: &[u8]) -> Result<Message> {
    // IMPLEMENT sketch (note the pattern — length-checked, gate-routed):
    //
    //   let (&tag, rest) = bytes.split_first().ok_or(Error::Validation("empty"))?;
    //   match tag {
    //     0x01 => {
    //       let a: &[u8;33] = rest.get(0..33)?.try_into().map_err(..)?;
    //       let sh = ValidatedPoint::from_bytes(a)?;   // <-- gate
    //       ...
    //     }
    //     _ => Err(Error::Validation("unknown tag")),
    //   }
    //
    // Every point/scalar goes through a `crypto::validate` constructor. No panics.
    Err(Error::Unimplemented("wire::parse_message: length-checked, gate-routed, panic-free parse"))
}

/// Serialize is the easy direction; still fixed-size and total.
pub fn serialize_message(_m: &Message) -> Vec<u8> {
    Vec::new() // IMPLEMENT
}
