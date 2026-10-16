//! NetBird's relay server (`relay/` in Go), in Rust, its QUIC listener on
//! Quinn. The same protocol, flags, variables, health check and listeners;
//! a Go relay client cannot tell the two apart. It replaces the Go relay
//! with its native Quinn listener, which crossed from Go into Rust for each
//! message read and each message written (Omnuv, 16 October 2026).
pub mod auth;
pub mod conn;
pub mod http;
pub mod messages;
pub mod metrics;
pub mod net;
pub mod quic;
pub mod relay;
pub mod server;
pub mod tls;
pub mod ws;
