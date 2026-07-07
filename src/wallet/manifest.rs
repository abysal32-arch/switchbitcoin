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
const FMT: u8 = 1;
/// Network binding: a testnet manifest must not take effect on a mainnet
/// wallet (cross-network replay). The prototype is testnet-only.
const NETWORK_TESTNET: u8 = 0;
const BODY_LEN: usize = 1 + 1 + 4 + 44 + 1 + 24 + 4 + 2; // 81
const ENVELOPE_LEN: usize = BODY_LEN + 64;

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
        let window = (self.params.margin as u64 + self.params.delta_buffer as u64)
            .saturating_sub(self.params.cofunding_window as u64)
            .saturating_sub(self.params.claim_confirm_allowance as u64);
        let mut prev_max = 0u64;
        for (min, max) in self.delay_bounds {
            if (min as u64) > (max as u64) {
                return Err(Error::Deadline("manifest: delay bound min exceeds max"));
            }
            if max as u64 > window {
                return Err(Error::Deadline(
                    "manifest: delay bound exceeds the worst-case claim window",
                ));
            }
            // Postures are ordered by decorrelation: widths must not regress.
            if (max as u64) < prev_max {
                return Err(Error::Deadline("manifest: posture maxima must be non-decreasing"));
            }
            prev_max = max as u64;
        }
        if self.cofunding_jitter_max > self.params.cofunding_window {
            return Err(Error::Deadline(
                "manifest: funding jitter exceeds the co-funding window",
            ));
        }
        if self.quorum_q == 0 {
            return Err(Error::Validation("manifest: quorum must be >= 1"));
        }
        Ok(())
    }

    // ---- canonical body (all integers LE) ----
    // [1 fmt=1][1 network][4 version][44 params][1 posture]
    // [(4 min)(4 max) x3][4 jitter][2 q]     = 81 bytes

    fn body_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(BODY_LEN);
        v.push(FMT);
        v.push(NETWORK_TESTNET);
        v.extend_from_slice(&self.version.to_le_bytes());
        v.extend_from_slice(&self.params.tier_d_sats.to_le_bytes());
        v.extend_from_slice(&self.params.delta_fee_sats.to_le_bytes());
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

/// How `ManifestStore::open` arrived at its current manifest.
#[derive(Debug, PartialEq, Eq)]
pub enum ManifestOpenReport {
    /// No stored manifest; running the compiled-in provisional baseline.
    ProvisionalFresh,
    /// The stored envelope verified; running it.
    Loaded { version: u32 },
    /// The stored envelope failed verification (tampered / wrong network /
    /// invariant violation). It was quarantined and the wallet FELL BACK to
    /// the provisional baseline. Surface this to the user: parameters
    /// changed underneath them.
    ProvisionalFallback { quarantined: PathBuf },
}

/// Durable holder of the wallet's current manifest. One per wallet data dir
/// (share the SwapStore's dir; the filenames do not collide).
pub struct ManifestStore {
    path: PathBuf,
    current: SignedManifest,
}

impl ManifestStore {
    /// Load the stored manifest (re-verifying its signature and invariants)
    /// or fall back to the compiled-in provisional baseline. Never fails
    /// open: a bad stored manifest is quarantined, not fatal.
    pub fn open(dir: &Path, root: &dyn ManifestTrustRoot) -> Result<(ManifestStore, ManifestOpenReport)> {
        std::fs::create_dir_all(dir)
            .map_err(|_| Error::Abort("manifest store dir unavailable"))?;
        let path = dir.join("manifest.current");
        let (current, report) = match std::fs::read(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                (SignedManifest::provisional(), ManifestOpenReport::ProvisionalFresh)
            }
            Err(_) => {
                // Transient I/O: run provisional for this session but leave
                // the file alone (it may verify next start).
                (SignedManifest::provisional(), ManifestOpenReport::ProvisionalFresh)
            }
            Ok(envelope) => match verify_manifest(&envelope, root) {
                Ok(m) => {
                    let v = m.version();
                    (m, ManifestOpenReport::Loaded { version: v })
                }
                Err(_) => {
                    let q = quarantine_manifest(&path)?;
                    (
                        SignedManifest::provisional(),
                        ManifestOpenReport::ProvisionalFallback { quarantined: q },
                    )
                }
            },
        };
        Ok((ManifestStore { path, current }, report))
    }

    pub fn current(&self) -> &SignedManifest {
        &self.current
    }

    /// Ingest a distribution envelope. Verifies signature + invariants, then
    /// applies the STRICTLY-MONOTONIC version gate: replay of the identical
    /// current manifest is an idempotent no-op; any other same-or-lower
    /// version — validly signed or not — is refused (downgrade defense).
    /// Persisted durably before it takes effect in memory.
    pub fn ingest(&mut self, envelope: &[u8], root: &dyn ManifestTrustRoot) -> Result<&SignedManifest> {
        let m = verify_manifest(envelope, root)?;
        if m == self.current {
            return Ok(&self.current); // idempotent re-ingest
        }
        if m.version() <= self.current.version() {
            return Err(Error::Ordering(
                "manifest version must strictly increase (downgrade/replay refused)",
            ));
        }
        // Durable write-then-apply (same discipline as the SwapStore).
        let tmp = self.path.with_extension("current.tmp");
        let mut f = std::fs::File::create(&tmp)
            .map_err(|_| Error::Abort("manifest tmp create failed"))?;
        f.write_all(envelope)
            .and_then(|()| f.sync_all())
            .map_err(|_| Error::Abort("manifest write/sync failed"))?;
        drop(f);
        std::fs::rename(&tmp, &self.path)
            .map_err(|_| Error::Abort("manifest rename failed"))?;
        self.current = m;
        Ok(&self.current)
    }

    /// v3.13: "Wallets refuse swaps across mismatched Δ_fee versions."
    /// The whole manifest is versioned as one unit, so any version mismatch
    /// refuses the swap (divergent params shrink the anonymity set).
    pub fn refuses_swap_with(&self, peer_manifest_version: u32) -> bool {
        peer_manifest_version != self.current.version()
    }
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
        // Provisional window = 72 + 24 - 12 - 6 = 78: a 79-block max could
        // push SL past its safe window at max skew.
        assert!(SignedManifest::compose(
            3,
            Params::testnet_provisional(),
            ClaimDelayPosture::Moderate,
            [(0, 6), (6, 36), (12, 79)],
            6,
            3,
        )
        .is_err());
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
        // jitter wider than the co-funding window
        assert!(SignedManifest::compose(
            3,
            Params::testnet_provisional(),
            ClaimDelayPosture::Moderate,
            [(0, 6), (6, 36), (12, 72)],
            13,
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

    #[test]
    fn tampered_stored_manifest_falls_back_to_provisional() {
        let dir = tempfile::tempdir().unwrap();
        {
            let (mut store, _) = ManifestStore::open(dir.path(), &ModeledTrustRoot).unwrap();
            store.ingest(&signed(2), &ModeledTrustRoot).unwrap();
        }
        // Tamper on disk.
        let p = dir.path().join("manifest.current");
        let mut raw = std::fs::read(&p).unwrap();
        raw[20] ^= 0x01;
        std::fs::write(&p, &raw).unwrap();

        let (store, report) = ManifestStore::open(dir.path(), &ModeledTrustRoot).unwrap();
        assert!(
            matches!(report, ManifestOpenReport::ProvisionalFallback { .. }),
            "got {report:?}"
        );
        assert_eq!(store.current().version(), 0, "must fall back to provisional");
        assert!(!p.exists(), "bad manifest must be quarantined aside");
    }

    #[test]
    fn version_mismatch_refuses_the_swap() {
        let dir = tempfile::tempdir().unwrap();
        let (mut store, _) = ManifestStore::open(dir.path(), &ModeledTrustRoot).unwrap();
        store.ingest(&signed(4), &ModeledTrustRoot).unwrap();
        assert!(!store.refuses_swap_with(4), "equal versions must proceed");
        assert!(store.refuses_swap_with(3), "older peer refused");
        assert!(store.refuses_swap_with(5), "newer peer refused (we update first)");
    }
}
