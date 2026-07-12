//! Increment 2a: the congestion CPFP bump executes end-to-end from a REAL
//! provisioned reserve (onboarding change → promoted reserve), via the public
//! wallet API: lease → build → enclave-sign → 1P1C submit → mark-spent. It
//! never strands the reserve on failure, and the completion consent gate holds.

use bitcoin::{
    absolute, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness,
};
use swapkey::chain::{ChainView, SimChain, SpendStatus};
use swapkey::settlement::params::Params;
use swapkey::tx::backstop::ANCHOR_VOUT;
use swapkey::wallet::keys::ModeledKeySource;
use swapkey::wallet::ledger::{
    acknowledge_linkage, acknowledge_phase0, BumpTarget, CoinState, Ledger, WalletClock,
    LINKAGE_WARNING, PHASE0_WARNING,
};
use swapkey::wallet::{run_cpfp_bump, BumpOutcome, CpfpBumpRequest, ModeledEnclave};
use swapkey::Error;

struct Clock(u64);
impl WalletClock for Clock {
    fn now_unix(&self) -> u64 {
        self.0
    }
}

fn txid(seed: u8) -> Txid {
    let mut b = [0u8; 32];
    b[0] = seed;
    Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array(b))
}

fn std_p2tr_spk(tag: u8) -> ScriptBuf {
    let mut v = vec![0x51u8, 0x20];
    v.extend_from_slice(&[tag; 32]);
    ScriptBuf::from_bytes(v)
}

/// The keyless P2A anchor scriptPubKey (`OP_1 <0x4e73>`), matching what the
/// CPFP builder commits to for the anchor prevout.
fn p2a_output(sats: u64) -> TxOut {
    TxOut {
        value: Amount::from_sat(sats),
        script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x02, 0x4e, 0x73]),
    }
}

/// Provision a real reserve coin through the public onboarding path.
/// Returns the ledger, keys, the reserve outpoint, and its amount. The tempdir
/// is returned so the sealed ledger file outlives the test body.
fn provision_reserve() -> (Ledger, ModeledKeySource, OutPoint, u64, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let mut ledger =
        Ledger::create(dir.path(), &ModeledEnclave, acknowledge_phase0(PHASE0_WARNING).unwrap())
            .unwrap();
    let keys = ModeledKeySource::new(&ModeledEnclave);
    let params = Params::testnet_provisional();
    let unit = params.tier_d_sats + params.delta_fee_sats;

    let deposit_op = OutPoint::new(txid(0x01), 0);
    let (idx, spk) = ledger.next_deposit_address(&keys).unwrap();
    ledger
        .register_deposit(
            deposit_op,
            unit + 80_000 + 1_000,
            100,
            idx,
            &spk,
            &keys,
            Some(acknowledge_phase0(PHASE0_WARNING).unwrap()),
        )
        .unwrap();
    let plan = ledger.split_deposit(deposit_op, &params, 1_000, &keys).unwrap();
    ledger.confirm_split(plan.txid, 105, &Clock(1_000)).unwrap();
    let change_op = OutPoint::new(plan.txid, plan.change_vout.expect("change output"));
    ledger.promote_change_to_reserve(change_op).unwrap();
    let amount = ledger.find(&change_op).unwrap().amount_sats;
    (ledger, keys, change_op, amount, dir)
}

/// A TRUC/v3 stalled parent with a P2A anchor at the last output, plus its
/// txid and vsize. Its single input is `parent_input` (funded on the sim).
fn parent_with_anchor(parent_input: OutPoint, main_sats: u64, anchor_sats: u64) -> (Vec<u8>, Txid, u64) {
    let tx = Transaction {
        version: Version(3),
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: parent_input,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut { value: Amount::from_sat(main_sats), script_pubkey: std_p2tr_spk(0x33) },
            p2a_output(anchor_sats),
        ],
    };
    let bytes = bitcoin::consensus::encode::serialize(&tx);
    (bytes, tx.compute_txid(), tx.vsize() as u64)
}

/// The reserve coin's on-chain UTXO must exist for the child's reserve input;
/// fund the anchor's parent input too. `anchor_sats` is a real non-dust P2A.
fn seed_chain(chain: &SimChain, parent_input: OutPoint, reserve_op: OutPoint, reserve_amount: u64) {
    chain.fund_with_amount(parent_input, 500_000, reserve_amount + 1_000_000);
    chain.fund_with_amount(reserve_op, 500_000, reserve_amount);
}

/// Happy path: a congested REFUND (silent, no consent) bumps from the reserve —
/// the 1P1C package is accepted, the reserve is marked spent, and the child
/// really spends both the parent anchor and the reserve.
#[test]
fn refund_bump_submits_package_and_spends_the_reserve() {
    let (mut ledger, keys, reserve_op, reserve_amount, _dir) = provision_reserve();
    let chain = SimChain::new(500_000);
    let anchor_sats = 240u64;
    let parent_input = OutPoint::new(txid(0x0A), 0);
    seed_chain(&chain, parent_input, reserve_op, reserve_amount);
    let (parent_bytes, parent_txid, parent_vsize) = parent_with_anchor(parent_input, 500_000, anchor_sats);

    let out = run_cpfp_bump(
        &mut ledger,
        &keys,
        &chain,
        CpfpBumpRequest {
            target: BumpTarget::Refund,
            linkage_ack: None, // refunds are silent
            lessee: [0xEE; 32],
            parent_bytes: &parent_bytes,
            parent_anchor: OutPoint::new(parent_txid, ANCHOR_VOUT),
            anchor_value_sats: anchor_sats,
            parent_fee_sats: 200,
            parent_vsize_vb: parent_vsize,
            target_feerate_sat_vb: 10,
            change_key_index: 0,
        },
    )
    .unwrap();

    let (child_txid, change_outpoint, change_amount) = match out {
        BumpOutcome::Submitted {
            reserve_outpoint,
            deposit_linked,
            child_txid,
            change_outpoint,
            change_amount_sats,
        } => {
            assert_eq!(reserve_outpoint, reserve_op);
            assert!(!deposit_linked, "a refund bump does not link the deposit");
            (child_txid, change_outpoint, change_amount_sats)
        }
        BumpOutcome::NoBump => panic!("the refund bump should have submitted"),
    };
    // The reserve is spent in the ledger and on the sim (child is in the mempool).
    assert_eq!(ledger.find(&reserve_op).unwrap().state, CoinState::Spent);
    assert!(matches!(chain.spend_status(reserve_op), SpendStatus::InMempool | SpendStatus::Confirmed(_)));
    assert!(matches!(
        chain.spend_status(OutPoint::new(parent_txid, ANCHOR_VOUT)),
        SpendStatus::InMempool | SpendStatus::Confirmed(_)
    ));

    // The child change is TRACKED as a new Reserve coin (the reserve value never
    // leaks out of the ledger). change = anchor + reserve − child_fee.
    assert_eq!(change_outpoint, OutPoint::new(child_txid, 0));
    let change = ledger.find(&change_outpoint).expect("child change tracked as a coin");
    // F5: PENDING until the child confirms — NOT leasable yet (an unconfirmed
    // change that could still evict must never poison the pool).
    assert_eq!(change.state, CoinState::PendingConfirm);
    assert_eq!(change.amount_sats, change_amount);
    let child_fee = (anchor_sats + reserve_amount) - change_amount;
    assert!(child_fee > 0 && child_fee < 10_000, "only the child fee leaves the pool");
    assert!(!ledger.has_leasable_reserve(1), "a pending change is not leasable yet");

    // Once the child CONFIRMS, the startup heal activates the change into the
    // leasable pool — replenishing it only after the change is real on chain.
    chain.mine();
    ledger.heal_pending_reserve_changes(&chain).unwrap();
    assert_eq!(ledger.find(&change_outpoint).unwrap().state, CoinState::Unspent);
    assert!(ledger.has_leasable_reserve(1), "the confirmed change replenishes the pool");
}

/// A COMPLETION bump links the reserve to the swap, so it needs the typed
/// consent — and on success the caller is told to persist the taint.
#[test]
fn completion_bump_requires_consent_and_reports_the_taint() {
    let (mut ledger, keys, reserve_op, reserve_amount, _dir) = provision_reserve();
    let chain = SimChain::new(500_000);
    let anchor_sats = 240u64;
    let parent_input = OutPoint::new(txid(0x0B), 0);
    seed_chain(&chain, parent_input, reserve_op, reserve_amount);
    let (parent_bytes, parent_txid, parent_vsize) = parent_with_anchor(parent_input, 500_000, anchor_sats);

    let req = |ack| CpfpBumpRequest {
        target: BumpTarget::Completion,
        linkage_ack: ack,
        lessee: [0xEE; 32],
        parent_bytes: &parent_bytes,
        parent_anchor: OutPoint::new(parent_txid, ANCHOR_VOUT),
        anchor_value_sats: anchor_sats,
        parent_fee_sats: 200,
        parent_vsize_vb: parent_vsize,
        target_feerate_sat_vb: 10,
        change_key_index: 0,
    };

    // No consent: refused before anything is leased; the reserve is untouched.
    assert!(matches!(
        run_cpfp_bump(&mut ledger, &keys, &chain, req(None)),
        Err(Error::Ordering(_))
    ));
    assert_eq!(ledger.find(&reserve_op).unwrap().state, CoinState::Unspent);

    // With consent: bumps, and the outcome flags the deposit-linkage taint.
    let ack = acknowledge_linkage(LINKAGE_WARNING).unwrap();
    match run_cpfp_bump(&mut ledger, &keys, &chain, req(Some(ack))).unwrap() {
        BumpOutcome::Submitted { deposit_linked, .. } => assert!(deposit_linked),
        BumpOutcome::NoBump => panic!("consented completion bump should submit"),
    }
    assert_eq!(ledger.find(&reserve_op).unwrap().state, CoinState::Spent);
}

/// No reserve provisioned ⇒ the executor falls back cleanly (NoBump), nothing
/// leased or spent.
#[test]
fn no_reserve_falls_back() {
    let dir = tempfile::tempdir().unwrap();
    let mut ledger =
        Ledger::create(dir.path(), &ModeledEnclave, acknowledge_phase0(PHASE0_WARNING).unwrap())
            .unwrap();
    let keys = ModeledKeySource::new(&ModeledEnclave);
    let chain = SimChain::new(500_000);
    let parent_input = OutPoint::new(txid(0x0C), 0);
    chain.fund_with_amount(parent_input, 500_000, 1_000_000);
    let (parent_bytes, parent_txid, parent_vsize) = parent_with_anchor(parent_input, 500_000, 240);

    let out = run_cpfp_bump(
        &mut ledger,
        &keys,
        &chain,
        CpfpBumpRequest {
            target: BumpTarget::Refund,
            linkage_ack: None,
            lessee: [0xEE; 32],
            parent_bytes: &parent_bytes,
            parent_anchor: OutPoint::new(parent_txid, ANCHOR_VOUT),
            anchor_value_sats: 240,
            parent_fee_sats: 200,
            parent_vsize_vb: parent_vsize,
            target_feerate_sat_vb: 10,
            change_key_index: 0,
        },
    )
    .unwrap();
    assert_eq!(out, BumpOutcome::NoBump);
}

/// A reserve too small for the required child fee ⇒ the build fails AFTER the
/// lease, so the lease must be RELEASED (never stranded) and the coin stays
/// leasable — the fund-safety property of the executor.
#[test]
fn undersized_reserve_releases_the_lease() {
    let (mut ledger, keys, reserve_op, reserve_amount, _dir) = provision_reserve();
    let chain = SimChain::new(500_000);
    let parent_input = OutPoint::new(txid(0x0D), 0);
    seed_chain(&chain, parent_input, reserve_op, reserve_amount);
    let (parent_bytes, parent_txid, parent_vsize) = parent_with_anchor(parent_input, 500_000, 240);

    // A feerate high enough that required_child_fee exceeds the reserve, so
    // build_cpfp_bump rejects (fee > reserve) — AFTER the lease is taken.
    let out = run_cpfp_bump(
        &mut ledger,
        &keys,
        &chain,
        CpfpBumpRequest {
            target: BumpTarget::Refund,
            linkage_ack: None,
            lessee: [0xEE; 32],
            parent_bytes: &parent_bytes,
            parent_anchor: OutPoint::new(parent_txid, ANCHOR_VOUT),
            anchor_value_sats: 240,
            parent_fee_sats: 0,
            parent_vsize_vb: parent_vsize,
            target_feerate_sat_vb: 400, // ~400*(vsize+120) ≫ 80k reserve
            change_key_index: 0,
        },
    )
    .unwrap();

    assert_eq!(out, BumpOutcome::NoBump);
    // The lease was released: the reserve is Unspent again and re-leasable.
    assert_eq!(ledger.find(&reserve_op).unwrap().state, CoinState::Unspent);
    assert!(ledger.has_leasable_reserve(1));
}

/// A minimal v3 tx spending `input` to a standard P2TR output — so a reserve
/// outpoint can be consumed on chain to simulate the phantom.
fn spend(input: OutPoint, out_sats: u64) -> Vec<u8> {
    let tx = Transaction {
        version: Version(3),
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: input,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut { value: Amount::from_sat(out_sats), script_pubkey: std_p2tr_spk(0x55) }],
    };
    bitcoin::consensus::encode::serialize(&tx)
}

/// Review finding 6 (proactive sweep): a Reserve coin the ledger still counts
/// Unspent but whose outpoint is CONFIRMED spent on chain — the phantom a
/// crashed submit→persist window leaves behind — is marked Spent by
/// `sweep_spent_reserves`, so it never wins lease selection and disables the
/// pool. An unspent reserve is left untouched.
#[test]
fn sweep_spent_reserves_clears_a_phantom() {
    let (mut ledger, _keys, reserve_op, reserve_amount, _dir) = provision_reserve();
    let chain = SimChain::new(500_000);
    chain.fund_with_amount(reserve_op, 500_000, reserve_amount);

    // Nothing spent yet: the sweep is a no-op and the reserve stays leasable.
    assert!(ledger.sweep_spent_reserves(&chain).unwrap().is_empty());
    assert_eq!(ledger.find(&reserve_op).unwrap().state, CoinState::Unspent);

    // The reserve outpoint is consumed on chain (a prior bump's child) while
    // the ledger — crashed before persisting — still says Unspent: the phantom.
    chain.broadcast(&spend(reserve_op, reserve_amount - 500)).unwrap();
    chain.mine(); // Confirmed

    let swept = ledger.sweep_spent_reserves(&chain).unwrap();
    assert_eq!(swept, vec![reserve_op], "the phantom is swept");
    assert_eq!(ledger.find(&reserve_op).unwrap().state, CoinState::Spent);
    assert!(!ledger.has_leasable_reserve(1), "the phantom no longer counts as available");
}

/// Review finding 6 (submit-failure self-heal): if run_cpfp_bump leases a
/// reserve the ledger thinks is Unspent but the chain has already spent (the
/// phantom), the package submit fails on the double-spent input and the
/// executor marks the reserve Spent — NOT released back to Unspent — so it is
/// never re-selected. Contrast with a genuine undersize failure, where the
/// still-unspent reserve IS released (the existing test).
#[test]
fn run_cpfp_bump_self_heals_a_phantom_reserve_on_submit_failure() {
    let (mut ledger, keys, reserve_op, reserve_amount, _dir) = provision_reserve();
    let chain = SimChain::new(500_000);
    let parent_input = OutPoint::new(txid(0x0F), 0);
    seed_chain(&chain, parent_input, reserve_op, reserve_amount);
    let (parent_bytes, parent_txid, parent_vsize) = parent_with_anchor(parent_input, 500_000, 240);

    // Consume the reserve outpoint on chain BEFORE the bump — the ledger still
    // says Unspent (phantom), so lease_reserve will pick it and submit will
    // fail on the double-spend.
    chain.broadcast(&spend(reserve_op, reserve_amount - 500)).unwrap();
    chain.mine();

    let out = run_cpfp_bump(
        &mut ledger,
        &keys,
        &chain,
        CpfpBumpRequest {
            target: BumpTarget::Refund,
            linkage_ack: None,
            lessee: [0xEE; 32],
            parent_bytes: &parent_bytes,
            parent_anchor: OutPoint::new(parent_txid, ANCHOR_VOUT),
            anchor_value_sats: 240,
            parent_fee_sats: 200,
            parent_vsize_vb: parent_vsize,
            target_feerate_sat_vb: 10,
            change_key_index: 0,
        },
    )
    .unwrap();

    assert_eq!(out, BumpOutcome::NoBump);
    // Self-healed: the phantom is Spent (not Unspent), so it can never be
    // re-leased to fail again — the pool is not disabled.
    assert_eq!(ledger.find(&reserve_op).unwrap().state, CoinState::Spent);
    assert!(!ledger.has_leasable_reserve(1));
}

/// F4 (belt-and-braces): run_cpfp_bump must NOT bump a parent that is already
/// CONFIRMED — it returns NoBump WITHOUT leasing or spending the reserve. A
/// confirmed parent needs no CPFP; bumping it would burn a reserve key on a
/// mined tx (the classifier guards its own side, but this is the last line
/// before a reserve is issued, covering any stale caller observation).
#[test]
fn bump_refuses_a_confirmed_parent() {
    let (mut ledger, keys, reserve_op, reserve_amount, _dir) = provision_reserve();
    let chain = SimChain::new(500_000);
    let anchor_sats = 240u64;
    let parent_input = OutPoint::new(txid(0x0C), 0);
    seed_chain(&chain, parent_input, reserve_op, reserve_amount);
    let (parent_bytes, parent_txid, parent_vsize) =
        parent_with_anchor(parent_input, 500_000, anchor_sats);

    // Confirm the parent on chain (spend_txid(parent_input) == parent_txid).
    chain.broadcast(&parent_bytes).unwrap();
    chain.mine();
    assert!(matches!(chain.spend_status(parent_input), SpendStatus::Confirmed(_)));

    let out = run_cpfp_bump(
        &mut ledger,
        &keys,
        &chain,
        CpfpBumpRequest {
            target: BumpTarget::Refund,
            linkage_ack: None,
            lessee: [0xEE; 32],
            parent_bytes: &parent_bytes,
            parent_anchor: OutPoint::new(parent_txid, ANCHOR_VOUT),
            anchor_value_sats: anchor_sats,
            parent_fee_sats: 200,
            parent_vsize_vb: parent_vsize,
            target_feerate_sat_vb: 10,
            change_key_index: 0,
        },
    )
    .unwrap();

    assert_eq!(out, BumpOutcome::NoBump, "a confirmed parent is not bumped");
    // The reserve was never leased/spent — the pool is intact.
    assert_eq!(ledger.find(&reserve_op).unwrap().state, CoinState::Unspent);
    assert!(ledger.has_leasable_reserve(1));
}

/// F5: an EVICTED CPFP child must not permanently poison the reserve pool. On a
/// successful bump the change is parked `PendingConfirm` (source reserve as
/// `parent`); if the package is then evicted (congestion worsens), the source
/// reserve reads chain-Unspent again while the change never materialized. The
/// startup heal drops the phantom change AND restores the source reserve, so
/// the pool is leasable again — never silently disabled in the exact congestion
/// the backstop exists for.
#[test]
fn evicted_cpfp_child_does_not_poison_the_reserve_pool() {
    let (mut ledger, keys, reserve_op, reserve_amount, _dir) = provision_reserve();
    let chain = SimChain::new(500_000);
    let anchor_sats = 240u64;
    let parent_input = OutPoint::new(txid(0x0D), 0);
    seed_chain(&chain, parent_input, reserve_op, reserve_amount);
    let (parent_bytes, parent_txid, parent_vsize) =
        parent_with_anchor(parent_input, 500_000, anchor_sats);

    let out = run_cpfp_bump(
        &mut ledger,
        &keys,
        &chain,
        CpfpBumpRequest {
            target: BumpTarget::Refund,
            linkage_ack: None,
            lessee: [0xEE; 32],
            parent_bytes: &parent_bytes,
            parent_anchor: OutPoint::new(parent_txid, ANCHOR_VOUT),
            anchor_value_sats: anchor_sats,
            parent_fee_sats: 200,
            parent_vsize_vb: parent_vsize,
            target_feerate_sat_vb: 10,
            change_key_index: 0,
        },
    )
    .unwrap();
    let change_op = match out {
        BumpOutcome::Submitted { change_outpoint, .. } => change_outpoint,
        BumpOutcome::NoBump => panic!("the bump should have submitted"),
    };
    assert_eq!(ledger.find(&reserve_op).unwrap().state, CoinState::Spent);
    assert_eq!(ledger.find(&change_op).unwrap().state, CoinState::PendingConfirm);

    // Congestion worsens: the package is EVICTED (child + change gone; the
    // source reserve is chain-Unspent again but still ledger-Spent — the poison).
    chain.evict(reserve_op);
    assert!(matches!(chain.spend_status(reserve_op), SpendStatus::Unspent));

    // The startup heal drops the phantom change and RESTORES the source reserve.
    ledger.heal_pending_reserve_changes(&chain).unwrap();
    assert!(ledger.find(&change_op).is_none(), "the phantom change is dropped");
    assert_eq!(
        ledger.find(&reserve_op).unwrap().state,
        CoinState::Unspent,
        "the source reserve is restored, not stranded Spent"
    );
    assert!(
        ledger.has_leasable_reserve(1),
        "the pool is not disabled — the reserve is leasable again"
    );
}
