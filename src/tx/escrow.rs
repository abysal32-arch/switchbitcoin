//! The Taproot 2-of-2 escrow output and the crypto/tx key-boundary crossing.
//!
//! Escrow = a P2TR output whose internal key is the MuSig2-aggregated 2-of-2
//! key, with ONE script-path leaf: a CSV relative-timelock refund payable to the
//! funder alone (`<N> OP_CSV OP_DROP <funder_xonly> OP_CHECKSIG`). Completion is
//! the key-path spend (MuSig2); refund is the script-path spend after N blocks.

use crate::{Error, Result};
use bitcoin::hashes::Hash as _;
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP};
use bitcoin::script::Builder;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::taproot::{ControlBlock, LeafVersion, TaprootBuilder, TaprootSpendInfo};
use bitcoin::{ScriptBuf, Sequence, XOnlyPublicKey};
use musig2::KeyAggContext;

/// Errors specific to escrow / key-boundary construction. Folded into the crate
/// error via `From` so the tx layer participates in the same abort posture.
#[derive(Debug)]
pub enum EscrowError {
    XOnly(&'static str),
    Taproot(&'static str),
    TweakMismatch,
    CsvRange,
}

impl From<EscrowError> for Error {
    fn from(e: EscrowError) -> Self {
        match e {
            EscrowError::XOnly(m) => Error::Validation(m),
            EscrowError::Taproot(m) => Error::Validation(m),
            EscrowError::TweakMismatch => {
                Error::Verification("taproot tweak mismatch: funded key != signed key")
            }
            EscrowError::CsvRange => {
                Error::Deadline("CSV exceeds the 16-bit BIP68 relative-height field")
            }
        }
    }
}

/// Cross a crypto-core point (secp 0.7 / secp256k1 0.31) into a bitcoin 0.32
/// x-only key by BYTES only. BIP340 x-only drops parity — correct for taproot
/// keys, which are even-Y by definition.
pub fn xonly_from_point(p: &secp::Point) -> Result<XOnlyPublicKey> {
    let bytes: [u8; 32] = p.serialize_xonly();
    XOnlyPublicKey::from_slice(&bytes)
        .map_err(|_| EscrowError::XOnly("invalid x-only key bytes crossing to bitcoin").into())
}

/// The refund tapscript leaf: `<N> OP_CSV OP_DROP <funder_xonly> OP_CHECKSIG`.
/// N is a relative BLOCK-height CSV (must fit the 16-bit BIP68 field).
fn refund_leaf_script(csv_blocks: u16, funder_xonly: &XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_sequence(Sequence::from_height(csv_blocks))
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_x_only_key(funder_xonly)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// A fully-constructed Taproot 2-of-2 escrow.
pub struct Escrow {
    /// The funding scriptPubKey (P2TR to the tweaked output key). Pay HERE.
    funding_spk: ScriptBuf,
    /// Taproot spend data (control block source for the refund path).
    spend_info: TaprootSpendInfo,
    /// The CSV refund leaf script (for control block + leaf hash lookups).
    refund_leaf: ScriptBuf,
    /// The 32-byte tapscript merkle root — the tweak input both stacks must share.
    merkle_root: [u8; 32],
    /// The BIP341 output key (x-only) — what the address commits to.
    output_key_xonly: [u8; 32],
    /// The relative CSV maturity (blocks) of the refund leaf.
    csv_blocks: u16,
}

impl Escrow {
    /// Build the escrow from the MuSig2 aggregate 2-of-2 key (UNTWEAKED internal
    /// key) and the funder's refund key, with a relative-block CSV refund.
    ///
    /// `internal_agg` is the untweaked aggregate (`KeyAggContext::aggregated_pubkey_untweaked`).
    /// `funder_refund` is the key that alone can sweep the refund leaf after CSV.
    pub fn new(
        internal_agg: &secp::Point,
        funder_refund: &secp::Point,
        csv_blocks: u32,
    ) -> Result<Self> {
        let csv_blocks: u16 = u16::try_from(csv_blocks).map_err(|_| EscrowError::CsvRange)?;
        let internal_xonly = xonly_from_point(internal_agg)?;
        let funder_xonly = xonly_from_point(funder_refund)?;
        let refund_leaf = refund_leaf_script(csv_blocks, &funder_xonly);

        let secp = Secp256k1::verification_only();
        let spend_info = TaprootBuilder::new()
            .add_leaf(0, refund_leaf.clone())
            .map_err(|_| EscrowError::Taproot("add_leaf"))?
            .finalize(&secp, internal_xonly)
            .map_err(|_| EscrowError::Taproot("taproot finalize"))?;

        let merkle_root = spend_info
            .merkle_root()
            .ok_or(EscrowError::Taproot("missing merkle root"))?
            .to_byte_array();
        let output_key_xonly = spend_info.output_key().serialize();
        let funding_spk = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());

        Ok(Escrow {
            funding_spk,
            spend_info,
            refund_leaf,
            merkle_root,
            output_key_xonly,
            csv_blocks,
        })
    }

    pub fn funding_script_pubkey(&self) -> &ScriptBuf {
        &self.funding_spk
    }

    pub fn merkle_root(&self) -> [u8; 32] {
        self.merkle_root
    }

    pub fn output_key_xonly(&self) -> [u8; 32] {
        self.output_key_xonly
    }

    pub fn refund_leaf(&self) -> &ScriptBuf {
        &self.refund_leaf
    }

    pub fn csv_blocks(&self) -> u16 {
        self.csv_blocks
    }

    /// The control block for a script-path refund spend.
    pub fn refund_control_block(&self) -> Result<ControlBlock> {
        self.spend_info
            .control_block(&(self.refund_leaf.clone(), LeafVersion::TapScript))
            .ok_or_else(|| EscrowError::Taproot("refund leaf not in tree").into())
    }
}

/// Apply the BIP341 taproot tweak to a MuSig2 context so signing produces a
/// valid KEY-PATH signature for the escrow's OUTPUT key, and PROVE it: the
/// tweaked aggregate must byte-equal the escrow's funded output key. Returns the
/// tweaked context on success, `Error::Verification` on mismatch (never a panic,
/// never a silently-wrong key).
///
/// Both stacks derive the tweak `t = tagged_hash("TapTweak", internal || root)`
/// from the SAME internal key and merkle root, so equality is expected — but a
/// funded-key/signed-key divergence is unspendable-fund territory, so we check.
pub fn taproot_tweaked_keyagg(
    untweaked: &KeyAggContext,
    escrow: &Escrow,
) -> Result<KeyAggContext> {
    let tweaked = untweaked
        .clone()
        .with_taproot_tweak(&escrow.merkle_root)
        .map_err(|_| EscrowError::Taproot("with_taproot_tweak"))?;
    let signed_key: [u8; 32] = tweaked.aggregated_pubkey::<secp::Point>().serialize_xonly();
    if signed_key != escrow.output_key_xonly {
        return Err(EscrowError::TweakMismatch.into());
    }
    Ok(tweaked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use musig2::KeyAggContext;
    use secp::Scalar;

    fn agg_ctx() -> (KeyAggContext, Scalar, Scalar, secp::Point, secp::Point) {
        let mut rng = rand::rng();
        let sk_a = Scalar::random(&mut rng);
        let sk_b = Scalar::random(&mut rng);
        let (pk_a, pk_b) = (sk_a * secp::G, sk_b * secp::G);
        let mut keys = [pk_a, pk_b];
        keys.sort_by_key(|p| p.serialize());
        let ctx = KeyAggContext::new(keys).expect("keys");
        (ctx, sk_a, sk_b, pk_a, pk_b)
    }

    #[test]
    fn escrow_builds_p2tr_and_tweak_equality_holds() {
        let (ctx, _sk_a, _sk_b, pk_a, _pk_b) = agg_ctx();
        let internal: secp::Point = ctx.aggregated_pubkey_untweaked();
        // Funder refund key = party A's key here (arbitrary for the test).
        let escrow = Escrow::new(&internal, &pk_a, 216).expect("escrow");

        // Funding spk is a 34-byte P2TR (OP_1 <32-byte program>).
        assert!(escrow.funding_script_pubkey().is_p2tr());

        // THE load-bearing invariant: tweaked signing key == funded output key.
        let tweaked = taproot_tweaked_keyagg(&ctx, &escrow).expect("tweak equality");
        assert_eq!(
            tweaked.aggregated_pubkey::<secp::Point>().serialize_xonly(),
            escrow.output_key_xonly()
        );

        // The refund control block resolves (leaf is in the tree).
        assert!(escrow.refund_control_block().is_ok());
    }

    #[test]
    fn csv_out_of_16bit_range_is_rejected() {
        let (ctx, ..) = agg_ctx();
        let internal: secp::Point = ctx.aggregated_pubkey_untweaked();
        assert!(matches!(
            Escrow::new(&internal, &internal, 70_000),
            Err(Error::Deadline(_))
        ));
    }
}
