//! Transaction layer (bitcoin 0.32) — the concrete Taproot realization of the
//! settlement composition. This is the OTHER HALF of the adaptor + timelock
//! composition the external cryptographer reviews: the escrow output, the real
//! BIP341 sighashes the MuSig2 signer signs, and the CSV refund timelocks.
//!
//! Version boundary (Req 1 discipline): the crypto core is secp256k1 0.31 (via
//! `secp`/`musig2`); `bitcoin` 0.32 carries its own secp256k1 0.29. These are
//! DISTINCT crates to the compiler. Keys cross ONLY as bytes — never pass one
//! version's key type where the other is expected. All crossing goes through the
//! helpers in `escrow` (x-only serialize -> `XOnlyPublicKey::from_slice`).
//!
//! THE load-bearing invariant of this layer (`escrow::taproot_tweaked_keyagg`):
//! the MuSig2 context we SIGN under, after the BIP341 taproot tweak, must yield
//! the exact x-only key the escrow ADDRESS commits to. If those differ, we would
//! fund an output we cannot spend. It is checked, not assumed.

pub mod escrow;
pub mod txbuild;

pub use escrow::{Escrow, EscrowError};
