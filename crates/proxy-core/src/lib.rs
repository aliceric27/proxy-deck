//! Pure logic for ProxyDesk: the persisted profile model, Mudfish node-list parsing, hand-added
//! proxy nodes, and translation of a profile into a sing-box 1.14 configuration.

pub mod custom;
pub mod model;
pub mod mudfish;
pub mod singbox;

pub use model::*;
