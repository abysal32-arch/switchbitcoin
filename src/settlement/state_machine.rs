//! Settlement state machine — the operational envelope (v3.14 §Operational State
//! Machine), rendered as TYPESTATES so illegal transitions don't compile.
//!
//! Phases advance by CONSUMING the prior state and returning the next, so you
//! cannot, e.g., broadcast a completion before the possession gate has produced
//! its witness. Each transition maps any failure to `Error::Abort`, which
//! `refund::run` turns into the completion-supersedes refund subroutine.
//! Typestate fields are PRIVATE: a `Possessing` cannot be forged with an
//! arbitrary `s_height` or unvalidated `Params` — the only way to hold one is
//! to have come through the transitions.
//!
//! Discovery is STUBBED (Requirement 5): a `PeerSession` (authenticated Tor
//! channel to the counterparty) is passed IN. This module never does matching,
//! overlay, or store-and-forward.
//!
//! GATES the external cryptographer must confirm are enforced here:
//!   G1 POSSESSION — `PossessionWitness` can only be built inside
//!      `Funded::run_adaptor_exchange`, after the assembled `CompletePreSig` for
//!      Comp->SH passes adaptor verification; the SL enabling partial is sent
//!      ONLY by `release_enabling_partial`, which demands that witness.
//!   G2 DEADLINE   — `broadcast_completion` refuses without runway + a
//!      `WatchtowerReceipt` bound to the already-armed `PreArmedRefund`. The
//!      evidence is a witness type, not a caller-supplied bool.

use crate::crypto::adaptor::{AdaptorPoint, AdaptorSecret, CompletePreSig};
use crate::crypto::{ValidatedFinalSig, ValidatedPoint};
use crate::settlement::params::Params;
use crate::settlement::refund::{PreArmedRefund, WatchtowerReceipt};
use crate::signing::{
    aggregate_nonces, assemble_complete_presig, commit_and_reveal, verify_partial,
    SigningSession, SingleSignerLease,
};
use crate::wire::{parse_message, serialize_message, Message};
use crate::{Error, Result};
use musig2::KeyAggContext;
use rand::Rng;
use secp::{Point, Scalar};
use std::rc::Rc;

/// Byte-level duplex channel to the counterparty. The (stubbed) discovery layer
/// provides the real authenticated Tor stream; tests provide an in-memory pair.
/// RECEIVING goes through `wire::parse_message`, so everything that enters the
/// state machine has passed the validation gate — a Transport cannot bypass it.
pub trait Transport {
    fn send(&mut self, bytes: &[u8]) -> Result<()>;
    fn recv(&mut self) -> Result<Vec<u8>>;
}

/// Opaque handle to the authenticated peer channel. Provided by the (stubbed)
/// discovery layer; here constructed manually (tests, hand-fed testnet drive).
pub struct PeerSession {
    swap_session_id: [u8; 32],
    transport: Box<dyn Transport>,
}

impl PeerSession {
    pub fn new(swap_session_id: [u8; 32], transport: Box<dyn Transport>) -> Self {
        PeerSession { swap_session_id, transport }
    }

    pub fn swap_session_id(&self) -> &[u8; 32] {
        &self.swap_session_id
    }

    fn send_msg(&mut self, m: &Message) -> Result<()> {
        self.transport.send(&serialize_message(m))
    }

    /// Every received byte string passes the validation gate here.
    fn recv_msg(&mut self) -> Result<Message> {
        let bytes = self.transport.recv()?;
        parse_message(&bytes)
    }
}

/// Role, derived from confirmed funding (v3.13). Not known until Funded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role { SecretHolder, SecretLearner }

// ----- Typestate phases -----------------------------------------------------

/// Phase 3–4: escrows constructed, refunds pre-agreed, funding in flight.
pub struct Funding {
    params: Params,
    peer: PeerSession,
}

/// Phase 4 complete: both escrows confirmed (dual-source, self-verifying), role
/// derived from txids + S. Holds the confirmation height S.
pub struct Funded {
    params: Params,
    peer: PeerSession,
    role: Role,
    s_height: u32,
}

/// Role-specific settlement material produced by the exchange. Encodes the
/// v3.11 lesson at the type level: SL's ability to complete its OWN leg is a
/// `CompletePreSig` it must actually hold, not an assumption.
enum RoleState {
    /// SH holds t itself (it minted it) and completes Comp->SH with it.
    SecretHolder { t: AdaptorSecret },
    /// SL holds the complete pre-signature for its own leg, completable once
    /// t is extracted from SH's broadcast.
    SecretLearner { presig_comp_sl: CompletePreSig },
}

/// Phase 5 complete: we hold what we need to EXTRACT or COMPLETE — i.e. the
/// possession gate G1 is satisfied. Fields private: not forgeable, not
/// tamperable; the deadline math below always runs against the params that
/// were validated on the way in.
pub struct Possessing {
    params: Params,
    role: Role,
    s_height: u32,
    presig_comp_sh: CompletePreSig, // verified (G1)
    t_point: AdaptorPoint,
    pre_armed_refund: PreArmedRefund, // exists BEFORE any broadcast (G2)
    role_state: RoleState,
}

/// Witness that G1 holds. Non-constructible except inside
/// `Funded::run_adaptor_exchange`, after the Comp->SH complete pre-signature
/// verified. Presenting it to `release_enabling_partial` is the ONLY way the
/// enabling partial goes on the wire. (Field is module-private: not even other
/// crate modules can mint one.)
pub struct PossessionWitness(());

/// Everything the exchange needs from the caller. Secrets stay in fields the
/// caller constructs; the exchange derives pubkeys and contexts itself.
pub struct ExchangeInputs {
    /// Our MuSig2 secret key for the 2-of-2.
    pub our_seckey: Scalar,
    /// Counterparty pubkey (validated on receipt during setup).
    pub their_pubkey: ValidatedPoint,
    /// Sighash of the Comp->SH completion (tx layer provides the real one).
    pub msg_comp_sh: [u8; 32],
    /// Sighash of the Comp->SL completion.
    pub msg_comp_sl: [u8; 32],
    /// Pre-armed refund — must exist BEFORE anything is released (G2 setup).
    pub pre_armed_refund: PreArmedRefund,
    /// SH: the adaptor secret it minted (`AdaptorSecret::generate`). SL: None.
    pub adaptor_secret: Option<AdaptorSecret>,
    /// Lease directory override (tests / alternate stores). None = default.
    pub lease_dir: Option<std::path::PathBuf>,
}

/// Canonical 2-of-2 key aggregation: BIP327 key aggregation is order-DEPENDENT,
/// so both parties MUST derive the same ordering. Rule: sort the two compressed
/// encodings lexicographically. (Any taproot tweak is applied by the tx layer
/// before sessions begin — see `SigningSession::begin` docs.)
fn canonical_key_agg(ours: Point, theirs: Point) -> Result<KeyAggContext> {
    let (a, b) = (ours.serialize(), theirs.serialize());
    if a == b {
        return Err(Error::Validation("both parties presented the same pubkey"));
    }
    let keys = if a < b { [ours, theirs] } else { [theirs, ours] };
    KeyAggContext::new(keys).map_err(|_| Error::Validation("key aggregation failed"))
}

fn expect_nonces(m: Message) -> Result<(crate::crypto::ValidatedPubNonce, crate::crypto::ValidatedPubNonce)> {
    match m {
        Message::Nonces { comp_sh, comp_sl } => Ok((comp_sh, comp_sl)),
        _ => Err(Error::Ordering("expected Nonces message")),
    }
}

fn expect_adaptor_point(m: Message) -> Result<AdaptorPoint> {
    match m {
        Message::AdaptorPointMsg(t) => Ok(t),
        _ => Err(Error::Ordering("expected AdaptorPoint message")),
    }
}

fn expect_sh_partials(m: Message) -> Result<(crate::crypto::ValidatedPartial, crate::crypto::ValidatedPartial)> {
    match m {
        Message::ShPartials { comp_sh, comp_sl } => Ok((comp_sh, comp_sl)),
        _ => Err(Error::Ordering("expected ShPartials message")),
    }
}

fn expect_sl_enabling(m: Message) -> Result<crate::crypto::ValidatedPartial> {
    match m {
        Message::SlEnablingPartial(p) => Ok(p),
        _ => Err(Error::Ordering("expected SlEnablingPartial message")),
    }
}

/// The ONLY function that puts SL's enabling partial on the wire, and it
/// demands the possession witness (G1). The witness is consumed: one release.
pub fn release_enabling_partial(
    witness: PossessionWitness,
    peer: &mut PeerSession,
    enabling_partial: crate::crypto::ValidatedPartial,
) -> Result<()> {
    let PossessionWitness(()) = witness; // consumed
    peer.send_msg(&Message::SlEnablingPartial(enabling_partial))
}

impl Funding {
    pub fn new(params: Params, peer: PeerSession) -> Self {
        Funding { params, peer }
    }

    /// Wait for both escrows to confirm via the self-verifying dual-source view,
    /// enforce the co-funding window, derive the role. CHAIN-LAYER FILL POINT.
    pub fn await_funded(self) -> Result<Funded> {
        self.params.validate()?; // ordering invariant (review item #5)
        // IMPLEMENT (chain layer): dual-source confirmation (>=1 self-verifying
        // source); enforce cofunding_window; compute S; derive Role from txids + S.
        Err(Error::Unimplemented("Funding::await_funded: dual-source confirm + cofunding window + role derivation"))
    }

    /// Hand-fed variant for the stubbed-discovery build (Requirement 5): the
    /// operator/test supplies the confirmed funding facts (role, S) that
    /// `await_funded` will derive from the chain view once the chain layer
    /// exists. Params are validated here exactly as in `await_funded`.
    pub fn funded_manual(self, role: Role, s_height: u32) -> Result<Funded> {
        self.params.validate()?;
        Ok(Funded { params: self.params, peer: self.peer, role, s_height })
    }
}

impl Funded {
    pub fn role(&self) -> Role {
        self.role
    }

    /// Run the interlocked adaptor exchange (Phase 5 messages 1–5), ending with
    /// a VERIFIED complete pre-signature for Comp->SH. Producing `Possessing` +
    /// `PossessionWitness` is the ONLY way past the gate.
    ///
    /// Ordering is mandatory and enforced lexically below:
    ///   1. both own sessions committed, THEN nonces revealed/exchanged
    ///   2. T received (validated) / sent
    ///   3. SH partials on BOTH completions; PartialSigVerify each
    ///   4. assemble + verify the CompletePreSig for Comp->SH   <-- G1
    ///   5. (SL) release the enabling partial ONLY via the witness
    /// Any verification failure => Err (=> Abort => refund). The pre-armed
    /// refund exists BEFORE the exchange begins (G2 setup): it is an input.
    pub fn run_adaptor_exchange(
        mut self,
        inputs: ExchangeInputs,
    ) -> Result<(Possessing, PossessionWitness)> {
        let our_pubkey = inputs.our_seckey * secp::G;
        let key_agg_ctx = canonical_key_agg(our_pubkey, inputs.their_pubkey.point())?;

        // INV-3: one signer per swap. Both sessions share the ONE lease.
        let lease = match &inputs.lease_dir {
            Some(dir) => SingleSignerLease::acquire_in(dir, self.peer.swap_session_id)?,
            None => SingleSignerLease::acquire(self.peer.swap_session_id)?,
        };

        // Fresh sessions (INV-4), one per completion message.
        let mut sess_sh = SigningSession::begin(
            Rc::clone(&lease), key_agg_ctx.clone(), inputs.our_seckey, inputs.msg_comp_sh,
        )?;
        let mut sess_sl = SigningSession::begin(
            Rc::clone(&lease), key_agg_ctx.clone(), inputs.our_seckey, inputs.msg_comp_sl,
        )?;

        // (1) Interlock: commit BOTH, then reveal/exchange nonces.
        let ours = commit_and_reveal(&mut sess_sh, &mut sess_sl)?;
        self.peer.send_msg(&Message::Nonces {
            comp_sh: ours.comp_sh.clone(),
            comp_sl: ours.comp_sl.clone(),
        })?;
        let (their_nonce_sh, their_nonce_sl) = expect_nonces(self.peer.recv_msg()?)?;

        let agg_nonce_sh = aggregate_nonces(&ours.comp_sh, &their_nonce_sh);
        let agg_nonce_sl = aggregate_nonces(&ours.comp_sl, &their_nonce_sl);

        match self.role {
            Role::SecretHolder => {
                // (2) SH publishes T = t*G; t never leaves this process.
                let t_secret = inputs
                    .adaptor_secret
                    .ok_or(Error::Ordering("SH must supply its adaptor secret"))?;
                let t_point = t_secret.point();
                self.peer.send_msg(&Message::AdaptorPointMsg(t_point.clone()))?;

                // (3) SH signs BOTH completions, adaptor-bound, and sends them.
                let p_sh = sess_sh.sign_partial(&agg_nonce_sh, &t_point)?;
                let p_sl = sess_sl.sign_partial(&agg_nonce_sl, &t_point)?;
                self.peer.send_msg(&Message::ShPartials {
                    comp_sh: p_sh.clone(),
                    comp_sl: p_sl.clone(),
                })?;

                // (5) Receive SL's enabling partial; verify BEFORE aggregation.
                let enabling = expect_sl_enabling(self.peer.recv_msg()?)?;
                verify_partial(
                    &key_agg_ctx, &enabling, &agg_nonce_sh, &t_point,
                    &inputs.their_pubkey, &their_nonce_sh, &inputs.msg_comp_sh,
                )?;

                // (4/G1 for SH) Assemble + verify the complete pre-signature.
                let presig_comp_sh = assemble_complete_presig(
                    &key_agg_ctx, &agg_nonce_sh, &t_point, &p_sh, &enabling,
                    inputs.msg_comp_sh,
                )?;
                presig_comp_sh.verify_adaptor(&t_point)?;

                let witness = PossessionWitness(());
                Ok((
                    Possessing {
                        params: self.params,
                        role: self.role,
                        s_height: self.s_height,
                        presig_comp_sh,
                        t_point,
                        pre_armed_refund: inputs.pre_armed_refund,
                        role_state: RoleState::SecretHolder { t: t_secret },
                    },
                    witness,
                ))
            }
            Role::SecretLearner => {
                // (2) Receive T (validated by the wire gate).
                let t_point = expect_adaptor_point(self.peer.recv_msg()?)?;

                // (3) Receive SH's partials on BOTH completions; verify each.
                let (sh_p_sh, sh_p_sl) = expect_sh_partials(self.peer.recv_msg()?)?;
                verify_partial(
                    &key_agg_ctx, &sh_p_sh, &agg_nonce_sh, &t_point,
                    &inputs.their_pubkey, &their_nonce_sh, &inputs.msg_comp_sh,
                )?;
                verify_partial(
                    &key_agg_ctx, &sh_p_sl, &agg_nonce_sl, &t_point,
                    &inputs.their_pubkey, &their_nonce_sl, &inputs.msg_comp_sl,
                )?;

                // Sign our own partials (sessions consumed: single-use).
                let sl_p_sh = sess_sh.sign_partial(&agg_nonce_sh, &t_point)?;
                let sl_p_sl = sess_sl.sign_partial(&agg_nonce_sl, &t_point)?;

                // (4) G1: assemble + verify the COMPLETE pre-sig for Comp->SH —
                // the tx we must extract from — BEFORE releasing anything.
                let presig_comp_sh = assemble_complete_presig(
                    &key_agg_ctx, &agg_nonce_sh, &t_point, &sl_p_sh, &sh_p_sh,
                    inputs.msg_comp_sh,
                )?;
                presig_comp_sh.verify_adaptor(&t_point)?;

                // Our own leg's complete pre-sig (v3.11 lesson: hold it, don't
                // assume it).
                let presig_comp_sl = assemble_complete_presig(
                    &key_agg_ctx, &agg_nonce_sl, &t_point, &sl_p_sl, &sh_p_sl,
                    inputs.msg_comp_sl,
                )?;
                presig_comp_sl.verify_adaptor(&t_point)?;

                // G1 satisfied — mint the witness, and ONLY NOW release the
                // enabling partial, through the witness-demanding gate.
                let witness = PossessionWitness(());
                release_enabling_partial(witness, &mut self.peer, sl_p_sh)?;

                // A fresh witness for the caller (the release consumed one; the
                // caller's copy proves the same fact, minted at the same point).
                let witness = PossessionWitness(());
                Ok((
                    Possessing {
                        params: self.params,
                        role: self.role,
                        s_height: self.s_height,
                        presig_comp_sh,
                        t_point,
                        pre_armed_refund: inputs.pre_armed_refund,
                        role_state: RoleState::SecretLearner { presig_comp_sl },
                    },
                    witness,
                ))
            }
        }
    }
}

/// The completed final signature for a leg, ready for the (chain-layer) Tor
/// broadcast. Producing this value is what the gates guard.
pub struct CompletionSig(pub [u8; 64]);

/// SL's claim plan: wait `delay_blocks` (privacy decorrelation), then broadcast
/// its completed leg. The delay is bounded so the claim still confirms before
/// S + delta_late (review item #5).
pub struct ClaimPlan {
    pub delay_blocks: u32,
    pub comp_sl_final: CompletionSig,
}

impl Possessing {
    pub fn role(&self) -> Role {
        self.role
    }

    pub fn s_height(&self) -> u32 {
        self.s_height
    }

    pub fn t_point(&self) -> &AdaptorPoint {
        &self.t_point
    }

    pub fn presig_comp_sh(&self) -> &CompletePreSig {
        &self.presig_comp_sh
    }

    /// SH ONLY: complete Comp->SH for broadcast, revealing t. Gate G2: refuses
    /// unless (a) there is runway to confirm before S + delta_early -
    /// delta_buffer (no first broadcast inside the buffer), and (b) an armed
    /// watchtower holds THIS pre-armed refund (witness receipt, not a bool).
    /// Broadcast is irrevocable reveal; the network send itself is the
    /// chain-layer fill.
    pub fn broadcast_completion(
        &self,
        current_height: u32,
        watchtower: &WatchtowerReceipt,
    ) -> Result<CompletionSig> {
        let t = match &self.role_state {
            RoleState::SecretHolder { t } => t,
            RoleState::SecretLearner { .. } => {
                return Err(Error::Ordering("only SH broadcasts Comp->SH"))
            }
        };
        // Total u64 math; validated params guarantee buffer < early.
        let deadline =
            self.s_height as u64 + self.params.delta_early as u64 - self.params.delta_buffer as u64;
        if current_height as u64 >= deadline {
            return Err(Error::Deadline(
                "inside delta_buffer: do not broadcast; fall back to pre-armed refund",
            ));
        }
        if !watchtower.matches(&self.pre_armed_refund) {
            return Err(Error::Deadline(
                "watchtower receipt does not cover the pre-armed refund; refuse to broadcast (G2)",
            ));
        }
        let sig = self.presig_comp_sh.complete_with(t)?;
        // IMPLEMENT (chain layer): dedicated Tor circuit, multi-peer broadcast,
        // babysit to confirmation, opt-in fee bump.
        Ok(CompletionSig(sig))
    }

    /// SL ONLY: on seeing Comp->SH's final signature in the mempool, extract t
    /// (via the verified CompletePreSig — G1), complete our own leg, and plan a
    /// randomized claim delay bounded so we still confirm before S + delta_late
    /// (review item #5). The bound is enforced by construction: the sampled
    /// delay cannot exceed `params.max_claim_delay`.
    pub fn claim_after_reveal(
        &self,
        final_sig_comp_sh: &ValidatedFinalSig,
        current_height: u32,
    ) -> Result<ClaimPlan> {
        let presig_comp_sl = match &self.role_state {
            RoleState::SecretLearner { presig_comp_sl } => presig_comp_sl,
            RoleState::SecretHolder { .. } => {
                return Err(Error::Ordering("only SL claims after reveal"))
            }
        };
        // Extraction (review item #2): t = s_final - s_hat, checked t*G == T.
        let t = self.presig_comp_sh.extract_secret(final_sig_comp_sh)?;

        // Bounded randomized decorrelation delay.
        let max_delay = self.params.max_claim_delay(self.s_height, current_height);
        // Never delay past the window; the sample space is [0, max_delay].
        let delay_blocks = if max_delay == 0 {
            0
        } else {
            rand::rng().random_range(0..=max_delay.min(u32::MAX as u64)) as u32
        };
        debug_assert!(
            current_height as u64 + delay_blocks as u64 + self.params.claim_confirm_allowance as u64
                <= self.s_height as u64 + self.params.delta_late()
                || max_delay == 0
        );

        let sig = presig_comp_sl.complete_with(&t)?;
        Ok(ClaimPlan { delay_blocks, comp_sl_final: CompletionSig(sig) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settlement::refund::confirm_watchtower_handoff;
    use std::sync::mpsc;

    /// In-memory duplex transport: two mpsc channels.
    struct ChannelTransport {
        tx: mpsc::Sender<Vec<u8>>,
        rx: mpsc::Receiver<Vec<u8>>,
    }

    impl Transport for ChannelTransport {
        fn send(&mut self, bytes: &[u8]) -> Result<()> {
            self.tx.send(bytes.to_vec()).map_err(|_| Error::Abort("peer hung up"))
        }
        fn recv(&mut self) -> Result<Vec<u8>> {
            self.rx.recv().map_err(|_| Error::Abort("peer hung up"))
        }
    }

    fn duplex() -> (ChannelTransport, ChannelTransport) {
        let (tx_a, rx_b) = mpsc::channel();
        let (tx_b, rx_a) = mpsc::channel();
        (ChannelTransport { tx: tx_a, rx: rx_a }, ChannelTransport { tx: tx_b, rx: rx_b })
    }

    struct PartySetup {
        seckey: Scalar,
        pubkey: Point,
    }

    fn keypair() -> PartySetup {
        let mut rng = rand::rng();
        let seckey = Scalar::random(&mut rng);
        PartySetup { seckey, pubkey: seckey * secp::G }
    }

    /// Full two-party in-process exchange + settlement crypto:
    ///   exchange -> SH broadcast authorization -> SL extraction -> SL claim.
    /// Proves G1/G2 wiring and the adaptor math end-to-end without a chain.
    #[test]
    fn two_party_exchange_extract_and_claim() {
        let sh_keys = keypair();
        let sl_keys = keypair();
        let (io_sh, io_sl) = duplex();
        let swap_id = [0xabu8; 32];
        let msg_comp_sh = [0x51u8; 32]; // tx layer will supply real sighashes
        let msg_comp_sl = [0x52u8; 32];
        let params = Params::testnet_provisional();
        let s_height = 100_000;

        let lease_dir_sh = tempfile::tempdir().expect("tempdir");
        let lease_dir_sl = tempfile::tempdir().expect("tempdir");

        // SH runs in a second thread (its sessions/leases never cross threads);
        // SL runs here. Byte channels are the only thing crossing.
        let sh_params = params.clone();
        let sl_pub = sl_keys.pubkey;
        let sh_handle = std::thread::spawn(move || -> Result<(CompletionSig, [u8; 33])> {
            let refund = PreArmedRefund::from_signed_tx(vec![0xaa; 64], s_height + 300)?;
            let receipt = confirm_watchtower_handoff(&refund, refund.fingerprint())?;
            let (t_secret, _t_point) = AdaptorSecret::generate()?;
            let peer = PeerSession::new(swap_id, Box::new(io_sh));
            let funded = Funding::new(sh_params, peer).funded_manual(Role::SecretHolder, s_height)?;
            let (possessing, _witness) = funded.run_adaptor_exchange(ExchangeInputs {
                our_seckey: sh_keys.seckey,
                their_pubkey: ValidatedPoint::from_bytes(&sl_pub.serialize())?,
                msg_comp_sh,
                msg_comp_sl,
                pre_armed_refund: refund,
                adaptor_secret: Some(t_secret),
                lease_dir: Some(lease_dir_sh.path().to_path_buf()),
            })?;
            let t_point_bytes = possessing.t_point().to_bytes();
            // G2-gated completion; broadcast itself is chain-layer.
            let sig = possessing.broadcast_completion(s_height + 10, &receipt)?;
            Ok((sig, t_point_bytes))
        });

        // SL side.
        let refund = PreArmedRefund::from_signed_tx(vec![0xbb; 64], s_height + 200).unwrap();
        let peer = PeerSession::new(swap_id, Box::new(io_sl));
        let funded = Funding::new(params, peer)
            .funded_manual(Role::SecretLearner, s_height)
            .expect("funded");
        let (sl_possessing, _witness) = funded
            .run_adaptor_exchange(ExchangeInputs {
                our_seckey: sl_keys.seckey,
                their_pubkey: ValidatedPoint::from_bytes(&sh_keys.pubkey.serialize()).unwrap(),
                msg_comp_sh,
                msg_comp_sl,
                pre_armed_refund: refund,
                adaptor_secret: None,
                lease_dir: Some(lease_dir_sl.path().to_path_buf()),
            })
            .expect("SL exchange");

        let (sh_completion, sh_t_point) = sh_handle.join().expect("SH thread").expect("SH side");

        // Both parties agreed on T.
        assert_eq!(sl_possessing.t_point().to_bytes(), sh_t_point);

        // "Mempool observation": SL sees SH's final signature bytes.
        let observed = ValidatedFinalSig::from_bytes(&sh_completion.0).expect("well-formed sig");
        let plan = sl_possessing
            .claim_after_reveal(&observed, s_height + 12)
            .expect("extract + claim");

        // The claim delay respects the review-item-#5 bound.
        let p = Params::testnet_provisional();
        assert!(
            (s_height + 12) as u64 + plan.delay_blocks as u64 + p.claim_confirm_allowance as u64
                <= s_height as u64 + p.delta_late()
        );

        // SL's completed leg is a real 64-byte BIP340 signature (verified
        // internally by complete_with against the aggregate key for Comp->SL).
        assert_eq!(plan.comp_sl_final.0.len(), 64);
    }

    #[test]
    fn broadcast_refuses_inside_buffer_and_without_receipt() {
        // Drive a minimal exchange to obtain a legitimate SH Possessing.
        let sh_keys = keypair();
        let sl_keys = keypair();
        let (io_sh, io_sl) = duplex();
        let swap_id = [0xcdu8; 32];
        let (msg_a, msg_b) = ([1u8; 32], [2u8; 32]);
        let params = Params::testnet_provisional();
        let s_height = 5_000;
        let lease_dir_sh = tempfile::tempdir().expect("tempdir");
        let lease_dir_sl = tempfile::tempdir().expect("tempdir");

        let sl_pub = sl_keys.pubkey;
        let sh_params = params.clone();
        let sh = std::thread::spawn(move || -> Result<()> {
            let refund = PreArmedRefund::from_signed_tx(vec![0x11; 32], s_height + 300)?;
            let good_receipt = confirm_watchtower_handoff(&refund, refund.fingerprint())?;
            // Receipt for a DIFFERENT refund must not satisfy G2.
            let other = PreArmedRefund::from_signed_tx(vec![0x22; 32], s_height + 300)?;
            let wrong_receipt = confirm_watchtower_handoff(&other, other.fingerprint())?;

            let (t_secret, _) = AdaptorSecret::generate()?;
            let peer = PeerSession::new(swap_id, Box::new(io_sh));
            let funded =
                Funding::new(sh_params, peer).funded_manual(Role::SecretHolder, s_height)?;
            let (possessing, _w) = funded.run_adaptor_exchange(ExchangeInputs {
                our_seckey: sh_keys.seckey,
                their_pubkey: ValidatedPoint::from_bytes(&sl_pub.serialize())?,
                msg_comp_sh: msg_a,
                msg_comp_sl: msg_b,
                pre_armed_refund: refund,
                adaptor_secret: Some(t_secret),
                lease_dir: Some(lease_dir_sh.path().to_path_buf()),
            })?;

            // Inside the buffer: deadline = S + 144 - 24 = S + 120.
            assert!(matches!(
                possessing.broadcast_completion(s_height + 120, &good_receipt),
                Err(Error::Deadline(_))
            ));
            // Wrong watchtower receipt: refused.
            assert!(matches!(
                possessing.broadcast_completion(s_height + 10, &wrong_receipt),
                Err(Error::Deadline(_))
            ));
            // Proper receipt + runway: authorized.
            assert!(possessing.broadcast_completion(s_height + 10, &good_receipt).is_ok());
            Ok(())
        });

        let refund = PreArmedRefund::from_signed_tx(vec![0x33; 32], s_height + 200).unwrap();
        let peer = PeerSession::new(swap_id, Box::new(io_sl));
        let funded = Funding::new(params, peer)
            .funded_manual(Role::SecretLearner, s_height)
            .expect("funded");
        let (_sl_possessing, _w) = funded
            .run_adaptor_exchange(ExchangeInputs {
                our_seckey: sl_keys.seckey,
                their_pubkey: ValidatedPoint::from_bytes(&sh_keys.pubkey.serialize()).unwrap(),
                msg_comp_sh: msg_a,
                msg_comp_sl: msg_b,
                pre_armed_refund: refund,
                adaptor_secret: None,
                lease_dir: Some(lease_dir_sl.path().to_path_buf()),
            })
            .expect("SL exchange");

        sh.join().expect("SH thread").expect("SH assertions");
    }
}
