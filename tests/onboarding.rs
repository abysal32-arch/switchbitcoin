//! Onboarding pipeline integration (wallet rank 3): the v3.13 Phase 0→4
//! lifecycle end-to-end on the SimChain, with REAL transactions and fees:
//!
//!   Phase 0  typed warning gate →
//!   Phase 1  deposit detected → auto-split into exactly-D+Δ_fee
//!            pre-encumbrance UTXOs + one change output (real broadcast,
//!            real fee accounting on the sim) →
//!   delay    randomized 24–72h encumbrance delay gates the coin →
//!   Phase 4  the whole eligible UTXO funds a Setup into a 2-of-2 escrow
//!            (zero change), confirmed on the sim.
//!
//! Proves the ledger's arithmetic and gating compose with the ALREADY-BUILT
//! Setup/escrow machinery — the swap layer consumes onboarded coins with no
//! adaptation.

use bitcoin::OutPoint;
use newkey::chain::{ChainView, SimChain, SpendStatus};
use newkey::settlement::params::Params;
use newkey::tx::escrow::Escrow;
use newkey::tx::setup::build_setup;
use newkey::wallet::keys::{KeyPurpose, KeySource, ModeledKeySource};
use newkey::wallet::ledger::{
    acknowledge_phase0, CoinClass, CoinState, Ledger, WalletClock, PHASE0_WARNING,
};
use newkey::wallet::ModeledEnclave;
use newkey::Error;

struct FixedClock(u64);
impl WalletClock for FixedClock {
    fn now_unix(&self) -> u64 {
        self.0
    }
}

#[test]
fn deposit_split_delay_setup_escrow_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let params = Params::testnet_provisional();
    let unit = params.tier_d_sats + params.delta_fee_sats;
    let t0 = 1_700_000_000u64;
    let chain = SimChain::new(800_000);

    // Phase 0: the typed gate (exact copy in, token out).
    let mut ledger = Ledger::create(
        dir.path(),
        &ModeledEnclave,
        acknowledge_phase0(PHASE0_WARNING).unwrap(),
    )
    .unwrap();
    let keys = ModeledKeySource::new(&ModeledEnclave);

    // A deposit of 2 units + change arrives at a fresh wallet address.
    let (dep_idx, _dep_spk) = ledger.next_deposit_address(&keys).unwrap();
    let dep_amount = 2 * unit + 80_000 + 1_500; // 2 units + change + fee
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
            Some(acknowledge_phase0(PHASE0_WARNING).unwrap()),
        )
        .unwrap();

    // Phase 1: auto-split — REAL tx, broadcast with real fee accounting.
    let plan = ledger
        .split_deposit(dep_op, &params, 1_500, &keys, &FixedClock(t0))
        .unwrap();
    assert_eq!(plan.pre_encumbrance_count, 2);
    assert_eq!(plan.change_sats, 80_000);
    chain.broadcast(&plan.tx_bytes).expect("split accepted by the chain");
    chain.mine();
    assert!(matches!(chain.spend_status(dep_op), SpendStatus::Confirmed(_)));
    ledger.confirm_split(plan.txid, chain.tip_height()).unwrap();

    // The randomized delay gates encumbrance: an hour in, still immature.
    assert!(matches!(
        ledger.lease_pre_encumbrance(unit, &FixedClock(t0 + 3600)),
        Err(Error::Deadline(_))
    ));

    // Past the maximum possible delay (72h + 1h jitter): eligible.
    let late = FixedClock(t0 + 73 * 3600 + 1);
    let coin = ledger
        .lease_pre_encumbrance(unit, &late)
        .unwrap()
        .expect("eligible pre-encumbrance coin");
    assert_eq!(coin.state, CoinState::Leased);

    // Phase 4: the WHOLE coin funds a Setup into a 2-of-2 escrow, no change.
    // Record-driven derivation: the coin carries its issuing purpose.
    assert_eq!(coin.key_purpose, KeyPurpose::PreEncumbrance);
    let funder_sk = keys.derive_seckey(coin.key_purpose, coin.key_index).unwrap();
    let mut rng = rand::rng();
    let peer_sk = secp::Scalar::random(&mut rng);
    let internal = newkey::settlement::state_machine::canonical_internal_key(
        funder_sk * secp::G,
        peer_sk * secp::G,
    )
    .unwrap();
    let escrow = Escrow::new(&internal, &(funder_sk * secp::G), params.delta_early).unwrap();
    let (setup_bytes, escrow_op) =
        build_setup(coin.outpoint, coin.amount_sats, &escrow, &funder_sk).unwrap();

    chain.broadcast(&setup_bytes).expect("setup accepted");
    chain.mine();
    assert!(
        matches!(chain.spend_status(coin.outpoint), SpendStatus::Confirmed(_)),
        "the pre-encumbrance coin was spent whole into the escrow"
    );
    assert!(
        chain.funding_height(escrow_op).is_some(),
        "the escrow outpoint is live on-chain"
    );
    ledger.mark_spent(coin.outpoint).unwrap();

    // Ledger invariants after the full pipeline: the change output is the
    // ONLY non-swap coin created, and every swap-path coin was exactly-sized.
    let coins = ledger.coins();
    let change: Vec<_> =
        coins.iter().filter(|c| c.class == CoinClass::OnboardingChange).collect();
    assert_eq!(change.len(), 1, "exactly one change output in the lifecycle");
    assert_eq!(change[0].amount_sats, 80_000);
    for c in coins.iter().filter(|c| c.class == CoinClass::PreEncumbrance) {
        assert_eq!(c.amount_sats, unit, "every pre-encumbrance coin exactly D + delta_fee");
    }
}
