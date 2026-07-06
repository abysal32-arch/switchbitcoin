//! Settlement state machine — the operational envelope (v3.14 §Operational State
//! Machine), rendered as TYPESTATES so illegal transitions don't compile.
//!
//! Phases advance by CONSUMING the prior state and returning the next, so you
//! cannot, e.g., broadcast a completion before the possession gate has produced
//! its witness. Each transition maps any failure to `Error::Abort`, which
//! `refund::run` turns into the completion-supersedes refund subroutine.
//!
//! Discovery is STUBBED (Requirement 5): a `PeerSession` (authenticated Tor
//! channel to the counterparty) is passed IN. This module never does matching,
//! overlay, or store-and-forward.
//!
//! GATES the external cryptographer must confirm are enforced here:
//!   G1 POSSESSION — `PossessionWitness` can only be built after verifying we
//!      hold a valid CompletePreSig for the tx we must extract from; the SL
//!      enabling partial is released ONLY on presentation of that witness.
//!   G2 DEADLINE   — `broadcast_completion` refuses without runway + armed
//!      watchtower + a pre-armed refund already on disk.

use crate::crypto::adaptor::{AdaptorPoint, CompletePreSig};
use crate::settlement::params::Params;
use crate::settlement::refund::PreArmedRefund;
use crate::{Error, Result};

/// Opaque handle to the authenticated peer channel. Provided by the (stubbed)
/// discovery layer; here constructed manually in tests.
pub struct PeerSession {
    pub swap_session_id: [u8; 32],
}

/// Role, derived from confirmed funding (v3.13). Not known until Funded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role { SecretHolder, SecretLearner }

// ----- Typestate phases -----------------------------------------------------

/// Phase 3–4: escrows constructed, refunds pre-agreed, funding in flight.
pub struct Funding {
    pub params: Params,
    pub peer: PeerSession,
}

/// Phase 4 complete: both escrows confirmed (dual-source, self-verifying), role
/// derived from txids + S. Holds the confirmation height S.
pub struct Funded {
    pub params: Params,
    pub peer: PeerSession,
    pub role: Role,
    pub s_height: u32,
}

/// Phase 5 mid-exchange: we hold what we need to EXTRACT (a verified complete
/// pre-signature for Comp->SH) — i.e. the possession gate G1 is satisfied.
pub struct Possessing {
    pub params: Params,
    pub role: Role,
    pub s_height: u32,
    pub presig_comp_sh: CompletePreSig, // verified (G1)
    pub t_point: AdaptorPoint,
    pub pre_armed_refund: PreArmedRefund, // exists BEFORE any broadcast (G2)
}

/// Witness that G1 holds. Non-constructible except via `enter_possession`, which
/// verifies the complete pre-signature. Presenting this is what authorizes
/// releasing SL's enabling partial.
pub struct PossessionWitness(pub(crate) ());

impl Funding {
    /// Wait for both escrows to confirm via the self-verifying dual-source view,
    /// enforce the co-funding window, derive the role. STUB the chain view here.
    pub fn await_funded(self) -> Result<Funded> {
        self.params.validate()?; // ordering invariant (review item #5)
        // IMPLEMENT: dual-source confirmation (>=1 self-verifying source);
        // enforce cofunding_window; compute S; derive Role from txids + S.
        Err(Error::Unimplemented("Funding::await_funded: dual-source confirm + cofunding window + role derivation"))
    }
}

impl Funded {
    /// Run the interlocked six-message adaptor exchange (see `signing`/`wire`),
    /// ending with a VERIFIED complete pre-signature for Comp->SH. Producing
    /// `Possessing` + `PossessionWitness` is the ONLY way past the gate.
    pub fn run_adaptor_exchange(self) -> Result<(Possessing, PossessionWitness)> {
        // IMPLEMENT (ordering is mandatory):
        //   1. commit both nonces, then reveal (concurrent-session interlock)
        //   2. receive T (validated)
        //   3. receive SH partials on BOTH completions; verify_partial each
        //   4. assemble + verify_adaptor the CompletePreSig for Comp->SH  <-- G1
        //   5. pre-arm our refund BEFORE releasing anything                <-- G2 setup
        //   6. ONLY NOW release SL's enabling partial (caller uses the witness)
        // Any verification failure => Err (=> Abort => refund).
        let _ = &self.peer;
        Err(Error::Unimplemented("Funded::run_adaptor_exchange: 6-message ordered exchange, gate G1"))
    }
}

impl Possessing {
    /// SH ONLY: broadcast Comp->SH, revealing t. Gate G2: refuse unless there is
    /// (a) enough block runway to confirm before S + delta_early - delta_buffer,
    /// and (b) an armed watchtower holding the pre-armed refund. Broadcast is
    /// irrevocable reveal.
    pub fn broadcast_completion(&self, current_height: u32, watchtower_armed: bool) -> Result<()> {
        if self.role != Role::SecretHolder {
            return Err(Error::Ordering("only SH broadcasts Comp->SH"));
        }
        let deadline = self.s_height + self.params.delta_early - self.params.delta_buffer;
        // runway check: must be able to confirm before the deadline; refuse if we
        // are already inside the buffer (no first broadcast inside the buffer).
        if current_height >= deadline {
            return Err(Error::Deadline("inside delta_buffer: do not broadcast; fall back to pre-armed refund"));
        }
        if !watchtower_armed {
            return Err(Error::Deadline("watchtower not armed with pre-armed refund; refuse to broadcast (G2)"));
        }
        // IMPLEMENT: complete_with(t) -> broadcast over dedicated Tor circuit,
        // multi-peer, Dandelion-style if available. Then babysit to confirmation.
        Err(Error::Unimplemented("Possessing::broadcast_completion: complete + Tor broadcast + bump to confirm"))
    }

    /// SL ONLY: on seeing Comp->SH in the mempool, apply the randomized claim
    /// delay (bounded so we still confirm before S + delta_late), extract t, and
    /// broadcast Comp->SL. Extraction uses the verified CompletePreSig (G1).
    pub fn claim_after_reveal(&self, _s_final_scalar: &crate::crypto::ValidatedPartial) -> Result<()> {
        if self.role != Role::SecretLearner {
            return Err(Error::Ordering("only SL claims after reveal"));
        }
        // IMPLEMENT: sample bounded claim delay; ASSERT worst-case still < S+delta_late
        // (review item #5); extract_secret; complete our own leg; Tor broadcast.
        let _ = self.presig_comp_sh.extract_secret(_s_final_scalar);
        Err(Error::Unimplemented("Possessing::claim_after_reveal: bounded delay + extract + broadcast"))
    }
}
