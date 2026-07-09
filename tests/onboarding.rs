//! Onboarding pipeline integration (wallet rank 3): the v3.13 Phase 0→4
//! lifecycle end-to-end on the SimChain, with REAL transactions and fees:
//!
//!   Phase 0  typed warning gate →
//!   Phase 1  deposit detected (spk binding verified) → auto-split into
//!            exactly-D+Δ_fee pre-encumbrance UTXOs + one change output at
//!            a shuffled position (real broadcast, real fee accounting) →
//!   bump     congestion stalls the split → RBF fee bump (same child keys)
//!            relays and confirms →
//!   delay    the randomized 24–72h delay anchors at CONFIRMATION and is
//!            double-anchored (wall clock AND chain height) →
//!   Phase 4  the whole eligible UTXO funds a Setup into a 2-of-2 escrow
//!            (zero change), confirmed on the sim.

use bitcoin::OutPoint;
use swapkey::chain::{ChainView, SimChain, SpendStatus};
use swapkey::settlement::params::Params;
use swapkey::tx::escrow::Escrow;
use swapkey::tx::setup::build_setup;
use swapkey::wallet::keys::{KeyPurpose, KeySource, ModeledKeySource};
use swapkey::wallet::ledger::{
    acknowledge_phase0, CoinClass, CoinState, Ledger, WalletClock, PHASE0_WARNING,
};
use swapkey::wallet::ModeledEnclave;
use swapkey::Error;

struct FixedClock(u64);
impl WalletClock for FixedClock {
    fn now_unix(&self) -> u64 {
        self.0
    }
}

#[test]
fn deposit_split_bump_delay_setup_escrow_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let params = Params::testnet_provisional();
    let unit = params.pre_encumbrance_sats(); // the pre-encumbrance coin: D + Δ_fee
    let t0 = 1_700_000_000u64;
    let chain = SimChain::new(800_000);
    let lessee = [0x5C; 32];

    // Phase 0: the typed gate (exact copy in, token out).
    let mut ledger = Ledger::create(
        dir.path(),
        &ModeledEnclave,
        acknowledge_phase0(PHASE0_WARNING).unwrap(),
    )
    .unwrap();
    let keys = ModeledKeySource::new(&ModeledEnclave);

    // A deposit of 2 units + change arrives at a fresh wallet address; the
    // ledger verifies the (key_index -> spk) binding before tracking it.
    let (dep_idx, dep_spk) = ledger.next_deposit_address(&keys).unwrap();
    let dep_amount = 2 * unit + 80_000 + 1_500;
    let dep_op = OutPoint::new(
        bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0xD0u8; 32])),
        0,
    );
    chain.fund_with_amount(dep_op, 800_000, dep_amount);
    ledger
        .register_deposit(
            dep_op,
            dep_amount,
            800_000,
            dep_idx,
            &dep_spk,
            &keys,
            Some(acknowledge_phase0(PHASE0_WARNING).unwrap()),
        )
        .unwrap();

    // Phase 1: auto-split — but the network is CONGESTED and the first fee
    // does not relay (the review's SplitPending-dead-end scenario).
    chain.set_congestion(3_000);
    let plan1 = ledger.split_deposit(dep_op, &params, 1_500, &keys).unwrap();
    assert!(
        matches!(chain.broadcast(&plan1.tx_bytes), Err(Error::Deadline(_))),
        "first attempt must stall under congestion"
    );

    // RBF fee bump from the ledger alone: same child keys, higher fee.
    let plan2 = ledger.bump_split_fee(dep_op, 5_000, &params, &keys).unwrap();
    assert_eq!(plan2.pre_encumbrance_count, 2);
    chain.broadcast(&plan2.tx_bytes).expect("bumped split relays");
    chain.mine();
    assert!(matches!(chain.spend_status(dep_op), SpendStatus::Confirmed(_)));
    let confirm_height = chain.tip_height();
    ledger
        .confirm_split(plan2.txid, confirm_height, &FixedClock(t0))
        .unwrap();

    // Attempt 1's children are gone; attempt 2's are live.
    assert!(ledger.coins().iter().all(|c| c.outpoint.txid != plan1.txid));

    // The delay anchors at CONFIRMATION (t0) and is double-anchored: clock
    // alone is not enough...
    assert!(matches!(
        ledger.lease_pre_encumbrance(unit, &FixedClock(t0 + 3600), chain.tip_height(), lessee),
        Err(Error::Deadline(_))
    ));
    let clock_late = FixedClock(t0 + 73 * 3600 + 1);
    assert!(matches!(
        ledger.lease_pre_encumbrance(unit, &clock_late, confirm_height + 1, lessee),
        Err(Error::Deadline(_))
    ));
    // ...the chain must ALSO have advanced past the height floor (72h of
    // delay ≈ up to 438 blocks; mine well past it).
    while chain.tip_height() < confirm_height + 500 {
        chain.mine();
    }
    let coin = ledger
        .lease_pre_encumbrance(unit, &clock_late, chain.tip_height(), lessee)
        .unwrap()
        .expect("eligible pre-encumbrance coin");
    assert_eq!(coin.state, CoinState::Leased);
    assert_eq!(coin.lessee, Some(lessee));

    // Phase 4: the WHOLE coin funds a Setup into a 2-of-2 escrow, no change.
    assert_eq!(coin.key_purpose, KeyPurpose::PreEncumbrance);
    let funder_sk = keys.derive_seckey(coin.key_purpose, coin.key_index).unwrap();
    let mut rng = rand::rng();
    let peer_sk = secp::Scalar::random(&mut rng);
    let internal = swapkey::settlement::state_machine::canonical_internal_key(
        funder_sk * secp::G,
        peer_sk * secp::G,
    )
    .unwrap();
    let escrow = Escrow::new(&internal, &(funder_sk * secp::G), params.delta_early).unwrap();
    let (setup_bytes, escrow_op) = build_setup(
        coin.outpoint,
        coin.amount_sats,
        params.escrow_amount_sats(),
        params.anchor_sats,
        &escrow,
        &funder_sk,
    )
    .unwrap();

    chain.set_congestion(0); // scheme (a): the Setup pays its own baked fee
    chain.broadcast(&setup_bytes).expect("setup accepted");
    chain.mine();
    assert!(
        matches!(chain.spend_status(coin.outpoint), SpendStatus::Confirmed(_)),
        "the pre-encumbrance coin was spent whole into the escrow"
    );
    assert!(chain.funding_height(escrow_op).is_some(), "escrow live on-chain");
    ledger.mark_spent(coin.outpoint).unwrap();

    // Ledger invariants after the full pipeline.
    let coins = ledger.coins();
    let change: Vec<_> =
        coins.iter().filter(|c| c.class == CoinClass::OnboardingChange).collect();
    assert_eq!(change.len(), 1, "exactly one change output in the lifecycle");
    for c in coins.iter().filter(|c| c.class == CoinClass::PreEncumbrance) {
        assert_eq!(c.amount_sats, unit, "every pre-encumbrance coin exactly D + delta_fee");
    }
}
