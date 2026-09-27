//! # mg-proto: generated bindings for the MorphGate wire contract
//!
//! Source of truth: `proto/morphgate/v1/{common,decision,config,challenge,policy_ir}.proto`.
//! Generated at build time by `build.rs` (protox + prost-build); nothing
//! generated is committed on the Rust side.
//!
//! The Decision Core (`mg-core`) has its own native types that mirror these
//! messages; the contract test in `tests/roundtrip.rs` checks that the enum
//! numbers and names agree. Wire-to-native conversions that need both sides
//! (the policy IR) live here too, in [`ir`], so `mg-core` stays free of prost.

/// Package `morphgate`.
pub mod morphgate {
    /// Package `morphgate.v1`.
    pub mod v1 {
        // Generated code: lint hygiene is prost-build's concern, and newer
        // clippy releases must not break CI on it.
        #![allow(clippy::all)]
        include!(concat!(env!("OUT_DIR"), "/morphgate.v1.rs"));
    }
}

pub use morphgate::v1;

pub mod ir;
