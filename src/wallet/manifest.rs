//! Signed, versioned parameter manifest (wallet rank 2).
//!
//! v3.13: "Δ_fee is a signed, versioned protocol constant. Equal-escrow
//! privacy depends on Δ_fee being identical for everyone in a tier, so it is
//! distributed and signed on the same trust path as the relay manifest,
//! never a local wallet setting. Wallets refuse swaps across mismatched
//! Δ_fee versions. [...] it is not user-editable."
//! v3.14: "The posture, the delay distribution, the widened co-funding
//! window, and the quorum size q are all signed, versioned parameters
//! distributed on the manifest trust path."
//! v3.16 §6: "All are distributed as signed, versioned parameters; none is a
//! free-form wallet setting."
//!
//! ENFORCEMENT MAP:
//!   * Signed — BIP340 over a tagged hash of the canonical body, verified
//!     against the PINNED operator key (`ManifestTrustRoot`). Verification
//!     uses the pinned libsecp256k1 bindings (Req 1) — no hand-rolled curve
//!     math, and none of this touches the settlement crypto modules (the
//!     frozen review surface).
//!   * Versioned — strictly-monotonic version gate at ingest: a replayed or
//!     downgraded manifest (even VALIDLY SIGNED) is refused; re-ingesting
//!     the identical current manifest is an idempotent no-op.
//!   * Ordering invariant — `Params::validate()` is asserted on EVERY ingest
//!     and every load, regardless of signature validity: a compromised
//!     operator key still cannot push params that violate the timelock
//!     ordering.
//!   * Not user-editable — `SignedManifest` fields are private; the only
//!     wallet-side constructors are `provisional()` (the compiled-in
//!     v3.16 §6 baseline, version 0) and signature-verified ingest.
//!     `compose` builds a NEW manifest but taking effect requires the
//!     operator secret key the wallet does not have.
//!   * Swap refusal — `refuses_swap_with(peer_version)`: any version
//!     mismatch refuses the swap (divergent Δ_fee shrinks the anonymity
//!     set; v3.13).
//!
//! The manifest is NETWORK-PUBLIC, so it is persisted as its signed envelope
//! (not sealed): the signature is the integrity root, re-verified on every
//! load, and there is no per-user data to keep confidential. A tampered
//! on-disk manifest is quarantined and the wallet falls back to the
//! compiled-in provisional baseline — fail-closed to known-good values.

use crate::settlement::params::Params;
use crate::{Error, Result};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::schnorr::Signature as SchnorrSig;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, XOnlyPublicKey};
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// Body-layout format byte (layout versioning, distinct from the manifest's
/// monotonic `version`).
const FMT: u8 = 3; // v3: +8 bytes cpfp_reserve_sats (v2 added anchor, setup_fee)
/// Network binding: a testnet manifest must not take effect on a mainnet
/// wallet (cross-network replay). The prototype is testnet-only.
const NETWORK_TESTNET: u8 = 0;
const BODY_LEN: usize = 1 + 1 + 4 + 68 + 1 + 24 + 4 + 2; // 105
/// Exact distribution-envelope length `[body || 64-byte BIP340 sig]`. Public
/// so the CLI ingest path can refuse a wrong-sized file BEFORE reading it
/// into memory (the envelope is fixed-length by construction).
pub const ENVELOPE_LEN: usize = BODY_LEN + 64;

/// The pinned manifest-signing key seam. In production this is the network
/// operator's (or threshold aggregate) x-only key, compiled into the wallet —
/// the manifest TRUST ROOT. Like `EnclaveKeyProvider`, consumers code against
/// the trait so the real root drops in without other changes.
pub trait ManifestTrustRoot {
    fn operator_xonly(&self) -> [u8; 32];
}

/// Prototype trust root: derived from a KNOWN modeled operator secret key
/// (`modeled_operator_seckey`) so tests and the prototype ops tooling can
/// sign. NOT a secret; a real build replaces this with the real pinned key
/// and the signing half lives only in ops tooling.
pub struct ModeledTrustRoot;

/// The modeled operator secret key (prototype only, publicly known).
pub fn modeled_operator_seckey() -> [u8; 32] {
    let mut sk = [0x42u8; 32];
    sk[31] = 0x01; // a valid, non-zero scalar
    sk
}

impl ManifestTrustRoot for ModeledTrustRoot {
    fn operator_xonly(&self) -> [u8; 32] {
        let secp = Secp256k1::new();
        let kp = Keypair::from_seckey_slice(&secp, &modeled_operator_seckey())
            .expect("modeled operator key is a valid scalar");
        kp.x_only_public_key().0.serialize()
    }
}

/// Build-time pinned trust root (Task 18, DECISION 3): wraps the REAL
/// operator x-only key compiled into a binary as a constant. Deliberately NOT
/// loadable from config — a `swapkey.toml` pin would reduce the whole
/// signed-manifest trust path to config-file security (any local writer of a
/// plaintext file could repoint the root, then feed manifests). The bytes are
/// not validated here; a non-key value fails every `verify_manifest` with
/// "invalid trust-root key" (fail closed, nothing ingests).
pub struct PinnedTrustRoot(pub [u8; 32]);

impl ManifestTrustRoot for PinnedTrustRoot {
    fn operator_xonly(&self) -> [u8; 32] {
        self.0
    }
}

/// SL's claim-delay posture (v3.14 "The One Open Dial"). The manifest both
/// publishes the three distributions and selects the ACTIVE posture
/// (moderate by default; testnet-tuned before mainnet).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimDelayPosture {
    Minimal,
    Moderate,
    Aggressive,
}

impl ClaimDelayPosture {
    fn to_byte(self) -> u8 {
        match self {
            ClaimDelayPosture::Minimal => 0,
            ClaimDelayPosture::Moderate => 1,
            ClaimDelayPosture::Aggressive => 2,
        }
    }
    fn from_byte(b: u8) -> Result<Self> {
        Ok(match b {
            0 => ClaimDelayPosture::Minimal,
            1 => ClaimDelayPosture::Moderate,
            2 => ClaimDelayPosture::Aggressive,
            _ => return Err(Error::Validation("manifest: unknown posture")),
        })
    }
    fn index(self) -> usize {
        self.to_byte() as usize
    }
}

/// A verified (or compiled-in) parameter manifest. Fields are PRIVATE: the
/// wallet cannot edit one into existence — only signature-verified ingest or
/// the compiled provisional baseline produce values of this type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedManifest {
    version: u32,
    params: Params,
    active_posture: ClaimDelayPosture,
    /// (min, max) randomized claim-delay bounds in blocks, indexed
    /// Minimal/Moderate/Aggressive. Statically bounded inside the
    /// worst-case claim window (see `validate`).
    delay_bounds: [(u32, u32); 3],
    /// Per-party co-funding jitter bound (blocks); lives inside the window.
    cofunding_jitter_max: u32,
    /// Discovery quorum size q (v3.14; carried for the post-review build).
    quorum_q: u16,
}

impl SignedManifest {
    /// The compiled-in v3.16 §6 baseline: version 0, testnet-provisional
    /// params, moderate posture. What a fresh (or fallen-back) wallet runs.
    pub fn provisional() -> Self {
        SignedManifest {
            version: 0,
            params: Params::testnet_provisional(),
            active_posture: ClaimDelayPosture::Moderate,
            // Worst-case claim window for the provisional params is
            // margin(72) + buffer(24) - cofund(12) - allowance(6) = 78.
            //
            // ⚠ CRYPTOGRAPHER REVIEW ITEM #5 (OPEN, needs a posture decision):
            // the ADVERSARY-PROOF (malicious-SH) window is only
            // margin - cofund - allowance = 54, so this top posture max (72)
            // exceeds it. The runtime `max_claim_delay` clamp binds the
            // ACHIEVABLE delay to the adversary-proof value, so there is no
            // runtime fund loss — but the STATED posture and this manifest
            // delay-bound check are calibrated to the loose honest-SH window.
            // Tightening the manifest window + this posture to <54 changes the
            // SIGNED manifest bytes (test vectors) and reduces the honest-early-
            // reveal privacy delay, so it is deferred to an owner/cryptographer
            // posture decision rather than retuned unilaterally.
            delay_bounds: [(0, 6), (6, 36), (12, 72)],
            cofunding_jitter_max: 6,
            quorum_q: 3,
        }
    }

    /// Build a NEW manifest for the ops tooling / tests to sign. Validated
    /// here AND at every ingest. Composing one does nothing to a wallet —
    /// taking effect requires the operator signature.
    pub fn compose(
        version: u32,
        params: Params,
        active_posture: ClaimDelayPosture,
        delay_bounds: [(u32, u32); 3],
        cofunding_jitter_max: u32,
        quorum_q: u16,
    ) -> Result<Self> {
        let m = SignedManifest {
            version,
            params,
            active_posture,
            delay_bounds,
            cofunding_jitter_max,
            quorum_q,
        };
        m.validate()?;
        Ok(m)
    }

    pub fn version(&self) -> u32 {
        self.version
    }
    pub fn params(&self) -> &Params {
        &self.params
    }
    pub fn active_posture(&self) -> ClaimDelayPosture {
        self.active_posture
    }
    /// (min, max) claim-delay bounds for a posture, in blocks.
    pub fn delay_bounds(&self, posture: ClaimDelayPosture) -> (u32, u32) {
        self.delay_bounds[posture.index()]
    }
    pub fn cofunding_jitter_max(&self) -> u32 {
        self.cofunding_jitter_max
    }
    pub fn quorum_q(&self) -> u16 {
        self.quorum_q
    }

    /// Stable identifier for wire comparison (tagged hash of the body).
    /// Two wallets agree on their manifest iff their ids are equal.
    pub fn id(&self) -> [u8; 32] {
        tagged_digest(&self.body_bytes())
    }

    /// The ordering invariant and the manifest's own static safety bounds —
    /// asserted on every compose, ingest, and load, REGARDLESS of signature
    /// validity. A compromised operator key cannot push:
    ///   * params violating the timelock ordering (`Params::validate`),
    ///   * a delay distribution whose maximum could push SL past its safe
    ///     window even at maximum co-funding skew,
    ///   * funding jitter wider than the co-funding window itself.
    fn validate(&self) -> Result<()> {
        self.params.validate()?;
        // Worst-case post-reveal claim window (blocks), at maximum
        // co-funding skew, after reserving the confirmation allowance.
        // Positive by Params::validate.
        //
        // ⚠ CRYPTOGRAPHER REVIEW ITEM #5 (OPEN): this window keeps the
        // honest-SH `delta_buffer` term, so it is looser than the adversary-
        // proof `margin - cofunding_window - allowance`. The runtime
        // `max_claim_delay` clamp is already adversary-proof, so this loose
        // DEFENSIVE bound causes no runtime loss; tightening it (and the
        // provisional posture) is deferred with the posture decision above.
        // `Params::validate`'s allowance bound IS already tightened, which
        // closes the reported exploit (an over-large allowance).
        let window = (self.params.margin as u64 + self.params.delta_buffer as u64)
            .saturating_sub(self.params.cofunding_window as u64)
            .saturating_sub(self.params.claim_confirm_allowance as u64);
        let mut prev_max = 0u64;
        let mut prev_min = 0u64;
        for (min, max) in self.delay_bounds {
            if (min as u64) > (max as u64) {
                return Err(Error::Deadline("manifest: delay bound min exceeds max"));
            }
            // STRICT: a max that merely REACHES the window budgets the claim
            // to confirm in the very block the SH refund matures (BIP68 makes
            // the refund includable in that block) — the boundary IS the
            // race. Must stay strictly inside. (Mirrors the -1 in
            // Params::max_claim_delay.)
            if max as u64 >= window {
                return Err(Error::Deadline(
                    "manifest: delay bound must stay strictly inside the worst-case claim window",
                ));
            }
            // Postures are ordered by decorrelation: neither endpoint may
            // regress from one posture to the next.
            if (max as u64) < prev_max || (min as u64) < prev_min {
                return Err(Error::Deadline("manifest: posture bounds must be non-decreasing"));
            }
            prev_max = max as u64;
            prev_min = min as u64;
        }
        // Jitter is PER-PARTY and the skews add: two parties each jittering
        // up to j can land 2j apart, so 2*jitter must fit in the window or
        // honest swaps get pushed into the skew-abort path.
        if self.cofunding_jitter_max as u64 * 2 > self.params.cofunding_window as u64 {
            return Err(Error::Deadline(
                "manifest: two-sided funding jitter exceeds the co-funding window",
            ));
        }
        if self.quorum_q == 0 {
            return Err(Error::Validation("manifest: quorum must be >= 1"));
        }
        Ok(())
    }

    // ---- canonical body (all integers LE) ----
    // [1 fmt=3][1 network][4 version][68 params: tier(8) fee(8) anchor(8)
    // setup_fee(8) cpfp_reserve(8) early(4) margin(4) buffer(4) allowance(4)
    // cofund(4) onboard_lo(4) onboard_hi(4)][1 posture]
    // [(4 min)(4 max) x3][4 jitter][2 q]     = 105 bytes

    fn body_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(BODY_LEN);
        v.push(FMT);
        v.push(NETWORK_TESTNET);
        v.extend_from_slice(&self.version.to_le_bytes());
        v.extend_from_slice(&self.params.tier_d_sats.to_le_bytes());
        v.extend_from_slice(&self.params.delta_fee_sats.to_le_bytes());
        v.extend_from_slice(&self.params.anchor_sats.to_le_bytes());
        v.extend_from_slice(&self.params.setup_fee_sats.to_le_bytes());
        v.extend_from_slice(&self.params.cpfp_reserve_sats.to_le_bytes());
        v.extend_from_slice(&self.params.delta_early.to_le_bytes());
        v.extend_from_slice(&self.params.margin.to_le_bytes());
        v.extend_from_slice(&self.params.delta_buffer.to_le_bytes());
        v.extend_from_slice(&self.params.claim_confirm_allowance.to_le_bytes());
        v.extend_from_slice(&self.params.cofunding_window.to_le_bytes());
        v.extend_from_slice(&self.params.onboarding_delay_hours.0.to_le_bytes());
        v.extend_from_slice(&self.params.onboarding_delay_hours.1.to_le_bytes());
        v.push(self.active_posture.to_byte());
        for (min, max) in self.delay_bounds {
            v.extend_from_slice(&min.to_le_bytes());
            v.extend_from_slice(&max.to_le_bytes());
        }
        v.extend_from_slice(&self.cofunding_jitter_max.to_le_bytes());
        v.extend_from_slice(&self.quorum_q.to_le_bytes());
        debug_assert_eq!(v.len(), BODY_LEN);
        v
    }

    /// Total parser for the fixed-length body. Any malformation is Err.
    fn from_body(b: &[u8]) -> Result<SignedManifest> {
        if b.len() != BODY_LEN {
            return Err(Error::Validation("manifest: wrong body length"));
        }
        let mut at = 0usize;
        if take_arr::<1>(b, &mut at)?[0] != FMT {
            return Err(Error::Validation("manifest: unknown format"));
        }
        if take_arr::<1>(b, &mut at)?[0] != NETWORK_TESTNET {
            return Err(Error::Validation("manifest: wrong network"));
        }
        let version = take_le_u32(b, &mut at)?;
        let params = Params {
            tier_d_sats: take_le_u64(b, &mut at)?,
            delta_fee_sats: take_le_u64(b, &mut at)?,
            anchor_sats: take_le_u64(b, &mut at)?,
            setup_fee_sats: take_le_u64(b, &mut at)?,
            cpfp_reserve_sats: take_le_u64(b, &mut at)?,
            delta_early: take_le_u32(b, &mut at)?,
            margin: take_le_u32(b, &mut at)?,
            delta_buffer: take_le_u32(b, &mut at)?,
            claim_confirm_allowance: take_le_u32(b, &mut at)?,
            cofunding_window: take_le_u32(b, &mut at)?,
            onboarding_delay_hours: (take_le_u32(b, &mut at)?, take_le_u32(b, &mut at)?),
        };
        let active_posture = ClaimDelayPosture::from_byte(take_arr::<1>(b, &mut at)?[0])?;
        let mut delay_bounds = [(0u32, 0u32); 3];
        for slot in &mut delay_bounds {
            *slot = (take_le_u32(b, &mut at)?, take_le_u32(b, &mut at)?);
        }
        let cofunding_jitter_max = take_le_u32(b, &mut at)?;
        let quorum_q = u16::from_le_bytes(take_arr::<2>(b, &mut at)?);
        let m = SignedManifest {
            version,
            params,
            active_posture,
            delay_bounds,
            cofunding_jitter_max,
            quorum_q,
        };
        // The ordering invariant is asserted on every parse — BEFORE any
        // signature question arises.
        m.validate()?;
        Ok(m)
    }
}

/// BIP340-style tagged hash: SHA256(SHA256(tag) || SHA256(tag) || body).
fn tagged_digest(body: &[u8]) -> [u8; 32] {
    let tag = sha256::Hash::hash(b"newkey/manifest/v1");
    let mut v = Vec::with_capacity(64 + body.len());
    v.extend_from_slice(tag.as_ref());
    v.extend_from_slice(tag.as_ref());
    v.extend_from_slice(body);
    sha256::Hash::hash(&v).to_byte_array()
}

/// Sign a manifest into its distribution envelope `[body || 64-byte sig]`.
/// Ops tooling / tests only: the wallet never holds `operator_seckey`.
pub fn sign_manifest(m: &SignedManifest, operator_seckey: &[u8; 32]) -> Result<Vec<u8>> {
    m.validate()?;
    let body = m.body_bytes();
    let secp = Secp256k1::new();
    let kp = Keypair::from_seckey_slice(&secp, operator_seckey)
        .map_err(|_| Error::Validation("invalid operator secret key"))?;
    let msg = Message::from_digest(tagged_digest(&body));
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);
    let mut out = body;
    out.extend_from_slice(sig.as_ref());
    Ok(out)
}

/// Verify an envelope against the pinned trust root and return the manifest.
/// TOTAL: malformed bytes, wrong network, invariant-violating params (even
/// validly signed), and bad signatures are all Err.
pub fn verify_manifest(
    envelope: &[u8],
    root: &dyn ManifestTrustRoot,
) -> Result<SignedManifest> {
    if envelope.len() != ENVELOPE_LEN {
        return Err(Error::Validation("manifest: wrong envelope length"));
    }
    let (body, sig_bytes) = envelope.split_at(BODY_LEN);
    // Parse + validate FIRST (the ordering invariant holds regardless of
    // signature), then verify the signature over the tagged digest.
    let m = SignedManifest::from_body(body)?;
    let secp = Secp256k1::verification_only();
    let sig = SchnorrSig::from_slice(sig_bytes)
        .map_err(|_| Error::Verification("manifest: malformed signature"))?;
    let key = XOnlyPublicKey::from_slice(&root.operator_xonly())
        .map_err(|_| Error::Verification("manifest: invalid trust-root key"))?;
    let msg = Message::from_digest(tagged_digest(body));
    secp.verify_schnorr(&sig, &msg, &key)
        .map_err(|_| Error::Verification("manifest: signature does not verify"))?;
    Ok(m)
}

/// Parse an envelope's BODY for display, WITHOUT any signature check — the
/// ops-tooling `inspect` verb (the manifest is network-public; showing its
/// fields makes no trust decision, and `compose` already lets anyone build an
/// unsigned `SignedManifest`). Total: malformed bytes and invariant-violating
/// params are Err. The WALLET never calls this — its only ingest paths remain
/// signature-verified (`verify_manifest` / `ManifestStore::ingest`).
pub fn inspect_envelope(envelope: &[u8]) -> Result<SignedManifest> {
    if envelope.len() != ENVELOPE_LEN {
        return Err(Error::Validation("manifest: wrong envelope length"));
    }
    SignedManifest::from_body(&envelope[..BODY_LEN])
}

/// How `ManifestStore::open` arrived at its current manifest.
#[derive(Debug, PartialEq, Eq)]
pub enum ManifestOpenReport {
    /// No stored manifest; running the compiled-in provisional baseline.
    ProvisionalFresh,
    /// The stored envelope verified; running it.
    Loaded { version: u32 },
    /// The stored envelope failed verification (tampered / wrong network /
    /// invariant violation). It was quarantined (or, if even the quarantine
    /// rename failed, left in place at the reported path) and the wallet
    /// FELL BACK to the provisional baseline — but the version FLOOR is
    /// kept, so old manifests still cannot replay. Surface to the user:
    /// parameters changed underneath them; re-sync the manifest.
    ProvisionalFallback { offending: PathBuf },
    /// The stored envelope VERIFIES but its version is below the recorded
    /// floor: someone restored an old manifest file (rollback). Quarantined;
    /// running provisional; floor kept. This is an ALARM, not a log line.
    RollbackDetected { quarantined: PathBuf, floor: u32 },
    /// The stored file could not be read (transient I/O). Running
    /// provisional FOR THIS SESSION; the file is left alone and may verify
    /// on the next start. Distinct from Fresh so it is never mistaken for a
    /// clean first run.
    ProvisionalTransient { path: PathBuf },
}

/// Durable holder of the wallet's current manifest. One per wallet data dir
/// (share the SwapStore's dir; the filenames do not collide). Holds an OS
/// file lock for its lifetime (same discipline as the SwapStore) so two
/// instances cannot race the version gate.
///
/// DOWNGRADE FLOOR: the highest version ever accepted is persisted in a
/// sidecar (`manifest.floor`) that SURVIVES quarantine of the manifest
/// itself — corrupting the stored manifest no longer resets the monotonic
/// gate to zero. Honest limit (documented, mirrors the store's anti-rollback
/// note): the sidecar lives on the same disk, so an attacker who can delete
/// BOTH files still wins; the real fix is the enclave-held monotonic
/// counter, the same real-infra seam as `platform_secure_key`.
pub struct ManifestStore {
    path: PathBuf,
    floor_path: PathBuf,
    current: SignedManifest,
    /// Highest version ever accepted (persisted; survives quarantine).
    floor: u32,
    /// Held for the store's lifetime; released by the OS on process death.
    _lock: std::fs::File,
}

impl ManifestStore {
    /// Load the stored manifest (re-verifying signature, invariants, AND the
    /// version floor) or fall back to the compiled-in provisional baseline.
    /// Never fails open on a bad manifest: quarantine (best-effort) + fall
    /// back + report. Fails only on unusable dir / lock contention.
    pub fn open(
        dir: &Path,
        root: &dyn ManifestTrustRoot,
    ) -> Result<(ManifestStore, ManifestOpenReport)> {
        std::fs::create_dir_all(dir)
            .map_err(|_| Error::Abort("manifest store dir unavailable"))?;
        let lock_path = dir.join(".manifest.lock");
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|_| Error::Abort("manifest lock file unavailable"))?;
        if lock.try_lock().is_err() {
            return Err(Error::Abort(
                "another process holds this manifest store (single-instance)",
            ));
        }
        let path = dir.join("manifest.current");
        let floor_path = dir.join("manifest.floor");
        let mut floor = read_floor(&floor_path);
        let (current, report) = match std::fs::read(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                (SignedManifest::provisional(), ManifestOpenReport::ProvisionalFresh)
            }
            Err(_) => (
                SignedManifest::provisional(),
                ManifestOpenReport::ProvisionalTransient { path: path.clone() },
            ),
            Ok(envelope) => match verify_manifest(&envelope, root) {
                Ok(m) if m.version() < floor => {
                    // A validly-signed but OLD manifest on disk: rollback.
                    let q = quarantine_manifest(&path).unwrap_or_else(|_| path.clone());
                    (
                        SignedManifest::provisional(),
                        ManifestOpenReport::RollbackDetected { quarantined: q, floor },
                    )
                }
                Ok(m) => {
                    let v = m.version();
                    // The floor may lag the stored manifest (crash between
                    // the envelope write and the floor write): catch it up.
                    if v > floor {
                        floor = v;
                        let _ = write_floor(&floor_path, floor); // best-effort
                    }
                    (m, ManifestOpenReport::Loaded { version: v })
                }
                Err(_) => {
                    // Quarantine best-effort: even if the rename fails, fall
                    // back rather than refusing to open (never-fatal).
                    let q = quarantine_manifest(&path).unwrap_or_else(|_| path.clone());
                    (
                        SignedManifest::provisional(),
                        ManifestOpenReport::ProvisionalFallback { offending: q },
                    )
                }
            },
        };
        Ok((ManifestStore { path, floor_path, current, floor, _lock: lock }, report))
    }

    pub fn current(&self) -> &SignedManifest {
        &self.current
    }

    /// True while running the compiled-in version-0 baseline. The rank-4
    /// orchestrator should surface this before the first swap: v0 wallets
    /// form their own (small, fingerprintable) anonymity partition, so
    /// syncing a real manifest first is the private choice.
    pub fn is_provisional(&self) -> bool {
        self.current.version() == 0
    }

    /// The persisted strictly-monotonic version floor (highest version ever
    /// accepted; survives tamper-quarantine of the manifest file). Surfaced
    /// so the operator can see WHY an ingest was version-gated.
    pub fn floor(&self) -> u32 {
        self.floor
    }

    /// Ingest a distribution envelope. Verifies signature + invariants, then
    /// applies the STRICTLY-MONOTONIC version gate against BOTH the current
    /// manifest and the persisted floor (which survives tamper-quarantine of
    /// the manifest file): replay of the identical current manifest is an
    /// idempotent no-op; any other same-or-lower version — validly signed or
    /// not — is refused. Persisted durably before it takes effect in memory.
    pub fn ingest(
        &mut self,
        envelope: &[u8],
        root: &dyn ManifestTrustRoot,
    ) -> Result<&SignedManifest> {
        let m = verify_manifest(envelope, root)?;
        if m == self.current {
            return Ok(&self.current); // idempotent re-ingest
        }
        if m.version() <= self.current.version() || m.version() <= self.floor {
            return Err(Error::Ordering(
                "manifest version must strictly increase (downgrade/replay refused)",
            ));
        }
        // Durable write-then-apply (same discipline as the SwapStore):
        // envelope first, then the floor, then memory. A crash between the
        // two writes leaves floor < stored version, which open() repairs.
        let tmp = self.path.with_extension("current.tmp");
        let mut f = std::fs::File::create(&tmp)
            .map_err(|_| Error::Abort("manifest tmp create failed"))?;
        f.write_all(envelope)
            .and_then(|()| f.sync_all())
            .map_err(|_| Error::Abort("manifest write/sync failed"))?;
        drop(f);
        std::fs::rename(&tmp, &self.path)
            .map_err(|_| Error::Abort("manifest rename failed"))?;
        write_floor(&self.floor_path, m.version())?;
        self.floor = m.version();
        self.current = m;
        Ok(&self.current)
    }

    /// v3.13: "Wallets refuse swaps across mismatched Δ_fee versions."
    /// Compares BOTH the version and the content id: version equality alone
    /// cannot detect an operator (or compromised key) signing two DIFFERENT
    /// manifests under one version — a silent anonymity-set split. The
    /// rank-4 wire exchanges (version, id) and calls this.
    pub fn refuses_swap_with(&self, peer_version: u32, peer_id: &[u8; 32]) -> bool {
        peer_version != self.current.version() || peer_id != &self.current.id()
    }
}

fn read_floor(path: &Path) -> u32 {
    match std::fs::read(path) {
        Ok(b) if b.len() == 4 => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        // Missing or malformed: floor 0. (An attacker deleting the sidecar
        // is the documented same-disk limit; accidental corruption of a
        // 4-byte fsync'd file is the case this degrades gracefully for.)
        _ => 0,
    }
}

fn write_floor(path: &Path, floor: u32) -> Result<()> {
    let tmp = path.with_extension("floor.tmp");
    let mut f =
        std::fs::File::create(&tmp).map_err(|_| Error::Abort("floor tmp create failed"))?;
    f.write_all(&floor.to_le_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|_| Error::Abort("floor write/sync failed"))?;
    drop(f);
    std::fs::rename(&tmp, path).map_err(|_| Error::Abort("floor rename failed"))?;
    Ok(())
}

fn quarantine_manifest(path: &Path) -> Result<PathBuf> {
    for n in 0u32..1000 {
        let q = path.with_extension(format!("current.bad{n}"));
        if !q.exists() {
            std::fs::rename(path, &q)
                .map_err(|_| Error::Abort("manifest quarantine failed"))?;
            return Ok(q);
        }
    }
    Err(Error::Abort("manifest quarantine namespace exhausted"))
}

fn take_arr<const N: usize>(b: &[u8], at: &mut usize) -> Result<[u8; N]> {
    let s = b
        .get(*at..*at + N)
        .ok_or(Error::Validation("manifest truncated"))?;
    *at += N;
    s.try_into().map_err(|_| Error::Validation("array slice"))
}

fn take_le_u32(b: &[u8], at: &mut usize) -> Result<u32> {
    Ok(u32::from_le_bytes(take_arr::<4>(b, at)?))
}

fn take_le_u64(b: &[u8], at: &mut usize) -> Result<u64> {
    Ok(u64::from_le_bytes(take_arr::<8>(b, at)?))
}

// ----- Tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn signed(version: u32) -> Vec<u8> {
        let m = SignedManifest::compose(
            version,
            Params::testnet_provisional(),
            ClaimDelayPosture::Moderate,
            [(0, 6), (6, 36), (12, 72)],
            6,
            3,
        )
        .unwrap();
        sign_manifest(&m, &modeled_operator_seckey()).unwrap()
    }

    #[test]
    fn round_trips_sign_verify_and_id_is_stable() {
        let env = signed(1);
        let m = verify_manifest(&env, &ModeledTrustRoot).expect("verify");
        assert_eq!(m.version(), 1);
        assert_eq!(m.params(), &Params::testnet_provisional());
        assert_eq!(m.active_posture(), ClaimDelayPosture::Moderate);
        assert_eq!(m.delay_bounds(ClaimDelayPosture::Aggressive), (12, 72));
        assert_eq!(m.cofunding_jitter_max(), 6);
        assert_eq!(m.quorum_q(), 3);
        // id is content-derived and stable across re-verification.
        let m2 = verify_manifest(&env, &ModeledTrustRoot).unwrap();
        assert_eq!(m.id(), m2.id());
        // ...and differs for different content.
        let other = verify_manifest(&signed(2), &ModeledTrustRoot).unwrap();
        assert_ne!(m.id(), other.id());
    }

    #[test]
    fn ordering_invariant_is_enforced_even_with_a_valid_signature() {
        // A compromised operator key cannot push ordering-violating params:
        // sign a manifest whose margin is 0 (delta_late == delta_early).
        let mut bad = SignedManifest::provisional();
        bad.version = 5;
        bad.params.margin = 0;
        // compose() would refuse; sign the raw struct via its body directly.
        let body = bad.body_bytes();
        let secp = Secp256k1::new();
        let kp = Keypair::from_seckey_slice(&secp, &modeled_operator_seckey()).unwrap();
        let msg = Message::from_digest(tagged_digest(&body));
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);
        let mut env = body;
        env.extend_from_slice(sig.as_ref());

        let err = verify_manifest(&env, &ModeledTrustRoot).unwrap_err();
        assert!(matches!(err, Error::Deadline(_)), "got {err:?}");
    }

    #[test]
    fn unsafe_delay_bounds_are_refused_even_signed() {
        // Provisional window = 72 + 24 - 12 - 6 = 78. STRICT bound: a max
        // that even REACHES 78 budgets the claim into the refund-maturity
        // block (the boundary IS the race) — 77 is the largest legal max.
        assert!(SignedManifest::compose(
            3,
            Params::testnet_provisional(),
            ClaimDelayPosture::Moderate,
            [(0, 6), (6, 36), (12, 78)],
            6,
            3,
        )
        .is_err());
        assert!(SignedManifest::compose(
            3,
            Params::testnet_provisional(),
            ClaimDelayPosture::Moderate,
            [(0, 6), (6, 36), (12, 77)],
            6,
            3,
        )
        .is_ok());
        // min > max
        assert!(SignedManifest::compose(
            3,
            Params::testnet_provisional(),
            ClaimDelayPosture::Moderate,
            [(7, 6), (6, 36), (12, 72)],
            6,
            3,
        )
        .is_err());
        // posture maxima regress
        assert!(SignedManifest::compose(
            3,
            Params::testnet_provisional(),
            ClaimDelayPosture::Moderate,
            [(0, 40), (6, 36), (12, 72)],
            6,
            3,
        )
        .is_err());
        // posture minima regress
        assert!(SignedManifest::compose(
            3,
            Params::testnet_provisional(),
            ClaimDelayPosture::Moderate,
            [(5, 6), (3, 36), (12, 72)],
            6,
            3,
        )
        .is_err());
        // TWO-SIDED jitter must fit the window: per-party 7 => 14 > 12.
        assert!(SignedManifest::compose(
            3,
            Params::testnet_provisional(),
            ClaimDelayPosture::Moderate,
            [(0, 6), (6, 36), (12, 72)],
            7,
            3,
        )
        .is_err());
        // zero quorum
        assert!(SignedManifest::compose(
            3,
            Params::testnet_provisional(),
            ClaimDelayPosture::Moderate,
            [(0, 6), (6, 36), (12, 72)],
            6,
            0,
        )
        .is_err());
    }

    #[test]
    fn tampering_wrong_root_and_malformed_envelopes_are_rejected() {
        let env = signed(1);

        // Flip a body byte: signature fails.
        let mut t = env.clone();
        t[10] ^= 0x01;
        assert!(verify_manifest(&t, &ModeledTrustRoot).is_err());

        // Flip a signature byte: fails.
        let mut t = env.clone();
        let last = t.len() - 1;
        t[last] ^= 0x01;
        assert!(verify_manifest(&t, &ModeledTrustRoot).is_err());

        // Wrong trust root: fails.
        struct OtherRoot;
        impl ManifestTrustRoot for OtherRoot {
            fn operator_xonly(&self) -> [u8; 32] {
                let secp = Secp256k1::new();
                let kp = Keypair::from_seckey_slice(&secp, &[0x33u8; 32]).unwrap();
                kp.x_only_public_key().0.serialize()
            }
        }
        assert!(verify_manifest(&env, &OtherRoot).is_err());

        // Truncated / oversized / garbage: total rejection.
        assert!(verify_manifest(&env[..env.len() - 1], &ModeledTrustRoot).is_err());
        let mut long = env.clone();
        long.push(0);
        assert!(verify_manifest(&long, &ModeledTrustRoot).is_err());
        assert!(verify_manifest(&[], &ModeledTrustRoot).is_err());

        // Wrong network byte (validly signed for testnet=1? no — re-sign a
        // body with network flipped): parser refuses before any sig check.
        let mut body = SignedManifest::provisional().body_bytes();
        body[1] = 1; // "mainnet"
        let secp = Secp256k1::new();
        let kp = Keypair::from_seckey_slice(&secp, &modeled_operator_seckey()).unwrap();
        let sig =
            secp.sign_schnorr_no_aux_rand(&Message::from_digest(tagged_digest(&body)), &kp);
        let mut cross = body;
        cross.extend_from_slice(sig.as_ref());
        assert!(verify_manifest(&cross, &ModeledTrustRoot).is_err());
    }

    #[test]
    fn store_version_gate_and_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let (mut store, report) = ManifestStore::open(dir.path(), &ModeledTrustRoot).unwrap();
        assert_eq!(report, ManifestOpenReport::ProvisionalFresh);
        assert_eq!(store.current().version(), 0);

        // Ingest v1: applies + persists.
        store.ingest(&signed(1), &ModeledTrustRoot).expect("v1");
        assert_eq!(store.current().version(), 1);

        // Idempotent re-ingest of the identical envelope: no-op Ok.
        store.ingest(&signed(1), &ModeledTrustRoot).expect("idempotent");
        assert_eq!(store.current().version(), 1);

        // Downgrade/replay refused even though validly signed. (version 1
        // again but different content would also be refused: build v1 with
        // a different posture.)
        let m1b = SignedManifest::compose(
            1,
            Params::testnet_provisional(),
            ClaimDelayPosture::Aggressive,
            [(0, 6), (6, 36), (12, 72)],
            6,
            3,
        )
        .unwrap();
        let env1b = sign_manifest(&m1b, &modeled_operator_seckey()).unwrap();
        assert!(matches!(
            store.ingest(&env1b, &ModeledTrustRoot).unwrap_err(),
            Error::Ordering(_)
        ));

        // Version gaps are fine; strictly increasing is the only rule.
        store.ingest(&signed(7), &ModeledTrustRoot).expect("v7");
        assert_eq!(store.current().version(), 7);

        // Fresh open loads the persisted manifest (re-verified).
        drop(store);
        let (store, report) = ManifestStore::open(dir.path(), &ModeledTrustRoot).unwrap();
        assert_eq!(report, ManifestOpenReport::Loaded { version: 7 });
        assert_eq!(store.current().version(), 7);
    }

    /// THE regression for the review's high finding: tamper-quarantine must
    /// NOT reset the monotonic floor — an old validly-signed manifest still
    /// cannot replay after a fallback.
    #[test]
    fn tampered_stored_manifest_falls_back_but_keeps_the_version_floor() {
        let dir = tempfile::tempdir().unwrap();
        {
            let (mut store, _) = ManifestStore::open(dir.path(), &ModeledTrustRoot).unwrap();
            store.ingest(&signed(7), &ModeledTrustRoot).unwrap();
        }
        // Tamper on disk.
        let p = dir.path().join("manifest.current");
        let mut raw = std::fs::read(&p).unwrap();
        raw[20] ^= 0x01;
        std::fs::write(&p, &raw).unwrap();

        let (mut store, report) = ManifestStore::open(dir.path(), &ModeledTrustRoot).unwrap();
        assert!(
            matches!(report, ManifestOpenReport::ProvisionalFallback { .. }),
            "got {report:?}"
        );
        assert_eq!(store.current().version(), 0, "must fall back to provisional");
        assert!(store.is_provisional());
        assert!(!p.exists(), "bad manifest must be quarantined aside");

        // The floor survived the quarantine: every historical version is
        // still refused — only something NEWER than v7 moves forward.
        for old in [1u32, 4, 7] {
            assert!(
                matches!(
                    store.ingest(&signed(old), &ModeledTrustRoot).unwrap_err(),
                    Error::Ordering(_)
                ),
                "v{old} must not replay after fallback"
            );
        }
        store.ingest(&signed(8), &ModeledTrustRoot).expect("genuinely newer");
        assert_eq!(store.current().version(), 8);
    }

    /// A validly-signed but OLD manifest file restored over the current one
    /// (rollback-by-file-swap) is detected against the floor at open.
    #[test]
    fn restored_old_manifest_file_is_detected_as_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let old_envelope = signed(2);
        {
            let (mut store, _) = ManifestStore::open(dir.path(), &ModeledTrustRoot).unwrap();
            store.ingest(&old_envelope, &ModeledTrustRoot).unwrap();
            store.ingest(&signed(6), &ModeledTrustRoot).unwrap();
        }
        // Attacker restores the captured v2 file over the v6 one.
        let p = dir.path().join("manifest.current");
        std::fs::write(&p, &old_envelope).unwrap();

        let (mut store, report) = ManifestStore::open(dir.path(), &ModeledTrustRoot).unwrap();
        assert!(
            matches!(report, ManifestOpenReport::RollbackDetected { floor: 6, .. }),
            "got {report:?}"
        );
        assert!(store.is_provisional(), "rollback runs provisional, not the old params");
        // And the gate still demands > 6.
        assert!(store.ingest(&signed(6), &ModeledTrustRoot).is_err());
        store.ingest(&signed(9), &ModeledTrustRoot).expect("newer");
    }

    #[test]
    fn second_manifest_store_instance_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (_store, _) = ManifestStore::open(dir.path(), &ModeledTrustRoot).unwrap();
        match ManifestStore::open(dir.path(), &ModeledTrustRoot) {
            Err(Error::Abort(_)) => {}
            Err(e) => panic!("wrong error: {e:?}"),
            Ok(_) => panic!("second instance must be refused"),
        }
    }

    #[test]
    fn version_or_content_mismatch_refuses_the_swap() {
        let dir = tempfile::tempdir().unwrap();
        let (mut store, _) = ManifestStore::open(dir.path(), &ModeledTrustRoot).unwrap();
        store.ingest(&signed(4), &ModeledTrustRoot).unwrap();
        let our_id = store.current().id();
        assert!(
            !store.refuses_swap_with(4, &our_id),
            "equal version AND content must proceed"
        );
        assert!(store.refuses_swap_with(3, &our_id), "older peer refused");
        assert!(store.refuses_swap_with(5, &our_id), "newer peer refused (we update first)");
        // Same version, DIFFERENT content (operator misbehavior / split
        // trust path): version equality alone must not pass the gate.
        let divergent = SignedManifest::compose(
            4,
            Params::testnet_provisional(),
            ClaimDelayPosture::Aggressive,
            [(0, 6), (6, 36), (12, 72)],
            6,
            3,
        )
        .unwrap();
        assert!(
            store.refuses_swap_with(4, &divergent.id()),
            "same-version divergent-content must refuse"
        );
    }
}
