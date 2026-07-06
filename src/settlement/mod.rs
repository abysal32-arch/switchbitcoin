//! Settlement core — the state machine, the two policy gates, and the refund
//! subroutine. Discovery is STUBBED (Requirement 5): `PeerSession` is handed in.

pub mod params;
pub mod state_machine;
pub mod refund;

pub use params::Params;
