//! Bitcoin Core relay-POLICY model (Core 28+/29+): dust, standardness, TRUC
//! (BIP431) topology, ephemeral dust, and 1P1C package checks.
//!
//! `SimChain` models consensus PHYSICS (single-spend, CSV maturity, RBF,
//! congestion). This module models the *policy* layer a real node applies
//! BEFORE a transaction ever reaches consensus — the layer the review packet's
//! §4.98 critical lives in (a positive-fee parent carrying a 0-value anchor is
//! dust-rejected at submission; a 0-fee Setup cannot relay standalone). The
//! checks here are deliberately the small, load-bearing subset the contract
//! transactions (Setup / Completion / Refund / CPFP bump) exercise, with the
//! exact numbers Core uses; anything beyond that subset is out of scope and
//! documented as such.
//!
//! FIDELITY NOTE (honest limits, for the review packet): this is a MODEL of
//! Core's policy, not Core. It checks dust thresholds, min-relay feerate,
//! output-script standardness (for the SPK types the protocol uses), tx-version
//! standardness (nVersion 1..=3), TRUC topology (v3-only unconfirmed chains,
//! 1-parent-1-child, child-size cap, and a transitive distinct-unconfirmed-
//! ANCESTOR count ≤ 1 — so a child spending two outputs of one parent is not
//! falsely rejected and a 3-deep v3 chain is correctly rejected), the
//! ephemeral-dust conditions, and package feerate.
//!
//! It does NOT model, and these are the review-surfaced deviations:
//! * (unmodeled) sigops-adjusted vsize, mempool eviction dynamics, TRUC sibling
//!   EVICTION (a second child of a TRUC parent is rejected here where Core 28+
//!   would consider evicting the incumbent — strictly stricter, the safe
//!   direction), and Script execution (signature validity is proven separately,
//!   bitcoin-side, in tests/taproot_swap.rs);
//! * (unmodeled, protocol never emits these) OP_RETURN datacarrier limits
//!   (size > 83 B / multi-push), MAX_STANDARD_TX_WEIGHT for non-v3 txs, and the
//!   generic 25-ancestor / 101-kvB mempool chain limits for non-TRUC txs — a
//!   tx of these shapes could FALSE-ACCEPT here, but the protocol builds none;
//! * (safe / stricter than Core, protocol never emits these) P2SH dust uses the
//!   546-sat legacy figure where Core computes 540; bare multisig, P2PK, and
//!   unknown-witness-version outputs are treated non-standard; and a non-v3
//!   0-fee package parent is not granted the package min-relay leniency.
//!
//! The protocol's own contract txs (Setup/Completion/Refund/CPFP bump) are all
//! v3, P2TR/P2A/P2WPKH, positive-fee, 1P1C — none of the deviations above are
//! reachable by them; re-confirm on the first real testnet broadcast.
//!
//! VERSION STANCE: the rules model Bitcoin Core 29.x and are conservative
//! for 28–31 with two documented deltas: (a) the ephemeral-dust acceptance
//! path exists only on Core 29.0+ (Core 28 rejects ANY below-dust output —
//! PR #30239); (b) the default min-relay feerate DROPPED from 1 sat/vB to
//! 0.1 sat/vB in Core 30.0 — we keep the STRICTER 1 sat/vB, so anything
//! accepted here relays on every version. Facts verified against Core
//! release notes 28.0–31.0, policy.h/policy.cpp/ephemeral_policy.cpp/
//! truc_policy.h, BIP 431/433, and Optech #324/#330 (2026-07 research
//! pass); re-confirm on the first real testnet broadcast.

use bitcoin::{Amount, Script, Transaction, TxOut};

/// Default minimum relay feerate: 1000 sat/kvB = 1 sat/vB (Core
/// `minrelaytxfee` through 29.x; Core 30.0 lowered the default to
/// 0.1 sat/vB — we keep the stricter figure so acceptance here implies
/// relay everywhere).
pub const MIN_RELAY_FEERATE_SAT_VB: u64 = 1;

/// Dust threshold for a P2A (pay-to-anchor, `OP_1 <0x4e73>`) output at the
/// default 3 sat/vB dust-relay feerate. Core's `GetDustThreshold`: output
/// serialized size (8 value + 1 len + 4 script = 13) + segwit spend cost
/// (32 + 4 + 1 + 107/4 + 4 = 67, integer division) = 80 bytes; 80 × 3 = 240.
pub const DUST_P2A_SATS: u64 = 240;

/// Dust threshold for a P2TR (or any v1+ witness program of 32 bytes) output:
/// (8 + 1 + 34) + 67 = 110 bytes; 110 × 3 = 330.
pub const DUST_P2TR_SATS: u64 = 330;

/// Dust threshold for P2WPKH: (8 + 1 + 22) + 67 = 98 bytes; 98 × 3 = 294.
pub const DUST_P2WPKH_SATS: u64 = 294;

/// Dust threshold for non-segwit outputs (the classic 546-sat figure).
pub const DUST_LEGACY_SATS: u64 = 546;

/// TRUC (BIP431): maximum vsize of a v3 transaction.
pub const TRUC_MAX_VSIZE_VB: u64 = 10_000;

/// TRUC (BIP431): maximum vsize of a v3 transaction that spends an
/// UNCONFIRMED v3 parent (the "child" of the 1P1C topology).
pub const TRUC_CHILD_MAX_VSIZE_VB: u64 = 1_000;

/// The canonical P2A scriptPubKey bytes: `OP_1 <0x4e73>`.
pub const P2A_SPK_BYTES: [u8; 4] = [0x51, 0x02, 0x4e, 0x73];

/// A policy rejection — the tx never reaches the mempool. Mirrors the class of
/// reject reason a real node returns from `testmempoolaccept`/`submitpackage`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyViolation {
    /// An output is below its type's dust threshold (and the ephemeral-dust
    /// conditions do not hold). Core: "dust".
    Dust { vout: usize, value: u64, threshold: u64 },
    /// The tx pays less than 1 sat/vB standalone. Core: "min relay fee not met".
    FeeBelowMinRelay { fee: u64, vsize: u64 },
    /// An output's scriptPubKey is not a standard type. Core: "scriptpubkey".
    NonStandardScript { vout: usize },
    /// The transaction nVersion is outside Core's standard range 1..=3.
    /// Core: "version".
    NonStandardVersion { version: i32 },
    /// A v3 tx exceeds 10,000 vB. Core: "v3-rule-violation".
    TrucTooLarge { vsize: u64 },
    /// A v3 tx spending an unconfirmed v3 parent exceeds 1,000 vB.
    TrucChildTooLarge { vsize: u64 },
    /// A non-v3 tx spends an unconfirmed v3 output, or a v3 tx spends an
    /// unconfirmed non-v3 output. Core: "v3-spend-violation".
    TrucVersionMix,
    /// A v3 tx would have more than one unconfirmed ancestor, or an
    /// unconfirmed v3 parent would gain a second descendant (1P1C).
    TrucTopology,
    /// Ephemeral-dust conditions violated: a below-dust output is only
    /// relayable when the tx pays ZERO fee, carries at most ONE dust output,
    /// and is submitted in a package whose child spends that dust output.
    /// Core: "dust" / "missing-ephemeral-spends".
    EphemeralDust(&'static str),
    /// Package-level failure (shape or feerate).
    Package(&'static str),
}

impl std::fmt::Display for PolicyViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyViolation::Dust { vout, value, threshold } => {
                write!(f, "policy: output {vout} is dust ({value} < {threshold} sats)")
            }
            PolicyViolation::FeeBelowMinRelay { fee, vsize } => {
                write!(f, "policy: fee {fee} below min relay for {vsize} vB")
            }
            PolicyViolation::NonStandardScript { vout } => {
                write!(f, "policy: output {vout} has a non-standard scriptPubKey")
            }
            PolicyViolation::NonStandardVersion { version } => {
                write!(f, "policy: non-standard tx version {version}")
            }
            PolicyViolation::TrucTooLarge { vsize } => {
                write!(f, "policy: TRUC tx too large ({vsize} vB > 10000)")
            }
            PolicyViolation::TrucChildTooLarge { vsize } => {
                write!(f, "policy: TRUC child too large ({vsize} vB > 1000)")
            }
            PolicyViolation::TrucVersionMix => {
                write!(f, "policy: v3/non-v3 unconfirmed spend mix")
            }
            PolicyViolation::TrucTopology => {
                write!(f, "policy: TRUC 1-parent-1-child topology violated")
            }
            PolicyViolation::EphemeralDust(s) => write!(f, "policy: ephemeral dust: {s}"),
            PolicyViolation::Package(s) => write!(f, "policy: package: {s}"),
        }
    }
}

/// True iff `spk` is the canonical P2A anchor script.
pub fn is_p2a(spk: &Script) -> bool {
    spk.as_bytes() == P2A_SPK_BYTES
}

/// Dust threshold for an output, by scriptPubKey type (default dust-relay
/// feerate). Unknown-but-standard types get the conservative legacy figure.
pub fn dust_threshold(spk: &Script) -> u64 {
    if is_p2a(spk) {
        DUST_P2A_SATS
    } else if spk.is_p2tr() || spk.is_p2wsh() {
        DUST_P2TR_SATS // 34-byte witness programs share the 330 figure
    } else if spk.is_p2wpkh() {
        DUST_P2WPKH_SATS
    } else {
        DUST_LEGACY_SATS
    }
}

/// Output-script standardness for the SPK types this protocol produces or its
/// tests fixture: witness programs (P2TR/P2WPKH/P2WSH/P2A), P2PKH, P2SH, and
/// OP_RETURN. An EMPTY script — the classic lazy test fixture — is
/// non-standard on a real node and is rejected here too.
pub fn is_standard_spk(spk: &Script) -> bool {
    is_p2a(spk)
        || spk.is_p2tr()
        || spk.is_p2wpkh()
        || spk.is_p2wsh()
        || spk.is_p2pkh()
        || spk.is_p2sh()
        || spk.is_op_return()
}

/// What the policy checker needs to know about each INPUT's previous output:
/// whether it is still unconfirmed (in-mempool), and if so the version of the
/// tx that created it and whether that parent already has another child.
#[derive(Clone, Copy, Debug)]
pub struct PrevoutCtx {
    /// True iff the previous output is an output of an UNCONFIRMED tx.
    pub unconfirmed_parent: bool,
    /// The parent tx's version (meaningful when `unconfirmed_parent`).
    pub parent_is_v3: bool,
    /// True iff that unconfirmed parent already has a different in-mempool
    /// descendant (TRUC allows exactly one).
    pub parent_has_other_child: bool,
}

/// Context for a tx submitted as the PARENT of a 1P1C package. `None` means
/// standalone submission (or the fee-bringing child, which gets no leniency).
#[derive(Clone, Copy, Debug)]
pub struct PackageCtx {
    /// True iff the package child spends EVERY below-dust output of this tx
    /// (Core's `CheckEphemeralSpends` / "missing-ephemeral-spends").
    pub dust_covered: bool,
}

/// The single-tx policy gate, run before physics. `fee` is sum(inputs) −
/// sum(outputs), already computed by the chain from resolved prevouts.
/// `unconfirmed_ancestor_count` is the number of DISTINCT unconfirmed ancestor
/// transactions (transitive), computed by the chain from its mempool graph —
/// counting ancestor TXS, not inputs (see the TRUC block). `package` is `Some`
/// only for the parent on the package path.
pub fn check_tx(
    tx: &Transaction,
    fee: u64,
    prevout_ctx: &[PrevoutCtx],
    unconfirmed_ancestor_count: usize,
    package: Option<PackageCtx>,
) -> Result<(), PolicyViolation> {
    let vsize = tx.vsize() as u64;
    let is_v3 = tx.version.0 == 3;

    // Core IsStandardTx: nVersion must be in 1..=3 ("version"). A version-0 or
    // version-4+ tx is non-standard and never relays, regardless of fee/dust.
    if tx.version.0 < 1 || tx.version.0 > 3 {
        return Err(PolicyViolation::NonStandardVersion { version: tx.version.0 });
    }

    // --- Output standardness + dust -----------------------------------------
    let mut dust_outputs = 0usize;
    for (vout, out) in tx.output.iter().enumerate() {
        if !is_standard_spk(&out.script_pubkey) {
            return Err(PolicyViolation::NonStandardScript { vout });
        }
        if out.script_pubkey.is_op_return() {
            continue; // provably unspendable; dust rules don't apply
        }
        let threshold = dust_threshold(&out.script_pubkey);
        if out.value < Amount::from_sat(threshold) {
            dust_outputs += 1;
            // Ephemeral-dust rule (Core 29+, PreCheckEphemeralTx): a
            // below-dust output relays ONLY if the tx pays EXACTLY ZERO fee
            // ("tx with dust output must be 0-fee") — THE §4.98 rejection:
            // a positive-fee contract tx carrying a 0-value anchor dies here.
            if fee != 0 {
                return Err(PolicyViolation::Dust {
                    vout,
                    value: out.value.to_sat(),
                    threshold,
                });
            }
            // MAX_DUST_OUTPUTS_PER_TX = 1.
            if dust_outputs > 1 {
                return Err(PolicyViolation::EphemeralDust("more than one dust output"));
            }
            // The dust must be swept by the package child (a 0-fee tx can
            // never relay standalone anyway — min-relay below).
            if package.map(|p| p.dust_covered) != Some(true) {
                return Err(PolicyViolation::EphemeralDust(
                    "0-fee parent with ephemeral dust must be submitted in a package whose child spends the dust",
                ));
            }
        }
    }

    // --- Fee: min-relay feerate ---------------------------------------------
    // BIP431/Core 28+: a TRUC (v3) PACKAGE PARENT may be below min-relay
    // (even 0-fee, dust or no dust) — the package feerate is judged instead
    // (checked by the package submitter). Everything else must clear
    // 1 sat/vB standalone; the fee-bringing child gets no leniency.
    let min_fee = vsize.saturating_mul(MIN_RELAY_FEERATE_SAT_VB);
    let truc_package_parent = is_v3 && package.is_some();
    if fee < min_fee && !truc_package_parent {
        return Err(PolicyViolation::FeeBelowMinRelay { fee, vsize });
    }

    // --- TRUC (BIP431) -------------------------------------------------------
    if is_v3 && vsize > TRUC_MAX_VSIZE_VB {
        return Err(PolicyViolation::TrucTooLarge { vsize });
    }
    for ctx in prevout_ctx {
        if !ctx.unconfirmed_parent {
            continue;
        }
        // v3 spends v3; non-v3 must not spend unconfirmed v3 (and vice versa).
        if ctx.parent_is_v3 != is_v3 {
            return Err(PolicyViolation::TrucVersionMix);
        }
        if is_v3 {
            if ctx.parent_has_other_child {
                return Err(PolicyViolation::TrucTopology);
            }
            if vsize > TRUC_CHILD_MAX_VSIZE_VB {
                return Err(PolicyViolation::TrucChildTooLarge { vsize });
            }
        }
    }
    // TRUC (BIP431): a v3 tx may have at most ONE unconfirmed ANCESTOR
    // transaction. The chain passes the transitive distinct-ancestor count, so
    // this counts distinct ancestor TXS (not inputs): a child spending two
    // outputs of one parent is ONE ancestor (not falsely rejected), and a
    // 3-deep unconfirmed v3 chain (G→P→C) is correctly rejected where
    // per-input counting saw only the direct parent.
    if is_v3 && unconfirmed_ancestor_count > 1 {
        return Err(PolicyViolation::TrucTopology);
    }

    Ok(())
}

/// 1P1C package shape gate (`submitpackage`): the child must spend at least
/// one output of the parent; computes whether every below-dust parent output
/// is swept by the child (the input to `check_tx`'s ephemeral-dust rule).
/// The PACKAGE feerate floor is the submitter's job (`package_meets_feerate`).
pub fn check_package_shape(
    parent: &Transaction,
    child: &Transaction,
) -> Result<PackageCtx, PolicyViolation> {
    let parent_txid = parent.compute_txid();
    let spends_of_parent: Vec<u32> = child
        .input
        .iter()
        .filter(|i| i.previous_output.txid == parent_txid)
        .map(|i| i.previous_output.vout)
        .collect();
    if spends_of_parent.is_empty() {
        return Err(PolicyViolation::Package("child does not spend the parent"));
    }
    // Every below-dust parent output must be consumed by the child.
    let mut dust_covered = true;
    for (vout, out) in parent.output.iter().enumerate() {
        if out.script_pubkey.is_op_return() || !is_standard_spk(&out.script_pubkey) {
            continue; // standardness is check_tx's job
        }
        if out.value < Amount::from_sat(dust_threshold(&out.script_pubkey))
            && !spends_of_parent.contains(&(vout as u32))
        {
            dust_covered = false;
        }
    }
    Ok(PackageCtx { dust_covered })
}

/// Package feerate: (fee_p + fee_c) / (vsize_p + vsize_c), floor-checked
/// against `floor_sat_vb` (Core evaluates CPFP acceptance on the package
/// feerate, not the child's own).
pub fn package_meets_feerate(
    parent: &Transaction,
    parent_fee: u64,
    child: &Transaction,
    child_fee: u64,
    floor_sat_vb: u64,
) -> bool {
    let vsize = (parent.vsize() as u64).saturating_add(child.vsize() as u64);
    let fee = parent_fee.saturating_add(child_fee);
    fee >= vsize.saturating_mul(floor_sat_vb)
}

/// Convenience for tests and fixtures: a TxOut and its policy verdict at a
/// glance — the exact reject a real node would give the CURRENT (pre-scheme-a)
/// contract shape.
pub fn output_is_dust(out: &TxOut) -> bool {
    !out.script_pubkey.is_op_return()
        && out.value < Amount::from_sat(dust_threshold(&out.script_pubkey))
}
