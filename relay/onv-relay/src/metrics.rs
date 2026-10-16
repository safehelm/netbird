//! The relay's counters, served in Prometheus's text format on the metrics
//! port under the Go relay's names where it has the same counter
use std::{
    fmt::Write,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

#[derive(Default)]
pub struct Metrics {
    pub sent: AtomicU64,
    pub received: AtomicU64,
    pub reconnections: AtomicU64,
    pub handshakes_rejected: AtomicU64,
    pub dropped_no_peer: AtomicU64,
    pub dropped_too_large: AtomicU64,
    pub dropped_write_failed: AtomicU64,
    peers_quic: AtomicU64,
    peers_ws: AtomicU64,
    auth_count: AtomicU64,
    auth_micros: AtomicU64,
}

impl Metrics {
    fn peers(&self, protocol: &str) -> &AtomicU64 {
        if protocol == "quic" { &self.peers_quic } else { &self.peers_ws }
    }

    pub fn peer_connected(&self, protocol: &str) {
        self.peers(protocol).fetch_add(1, Ordering::Relaxed);
    }

    pub fn peer_disconnected(&self, protocol: &str) {
        self.peers(protocol).fetch_sub(1, Ordering::Relaxed);
    }

    pub fn record_auth_time(&self, d: Duration) {
        self.auth_count.fetch_add(1, Ordering::Relaxed);
        self.auth_micros.fetch_add(d.as_micros() as u64, Ordering::Relaxed);
    }

    pub fn render(&self) -> String {
        let get = |a: &AtomicU64| a.load(Ordering::Relaxed) as f64;
        let mut s = String::new();
        let mut one = |name: &str, kind: &str, help: &str, rows: &[(&str, f64)]| {
            let _ = writeln!(s, "# HELP {name} {help}\n# TYPE {name} {kind}");
            for (labels, v) in rows {
                let _ = writeln!(s, "{name}{labels} {v}");
            }
        };
        one(
            "relay_transfer_sent_bytes_total",
            "counter",
            "Bytes of transport messages sent to peers",
            &[("", get(&self.sent))],
        );
        one(
            "relay_transfer_received_bytes_total",
            "counter",
            "Bytes of transport messages received from peers",
            &[("", get(&self.received))],
        );
        one(
            "relay_peers",
            "gauge",
            "Peers connected, by transport",
            &[("{transport=\"quic\"}", get(&self.peers_quic)), ("{transport=\"ws\"}", get(&self.peers_ws))],
        );
        one(
            "relay_peer_reconnections_total",
            "counter",
            "Peers that connected while their id was connected",
            &[("", get(&self.reconnections))],
        );
        one(
            "relay_handshakes_rejected_total",
            "counter",
            "Connections refused at the handshake",
            &[("", get(&self.handshakes_rejected))],
        );
        one(
            "relay_transport_dropped_total",
            "counter",
            "Transport messages not delivered, by reason",
            &[
                ("{reason=\"no_peer\"}", get(&self.dropped_no_peer)),
                ("{reason=\"too_large\"}", get(&self.dropped_too_large)),
                ("{reason=\"write_failed\"}", get(&self.dropped_write_failed)),
            ],
        );
        one(
            "relay_peer_authentication_seconds_count",
            "counter",
            "Handshakes completed",
            &[("", get(&self.auth_count))],
        );
        one(
            "relay_peer_authentication_seconds_sum",
            "counter",
            "Time from accept to authenticated, summed",
            &[("", get(&self.auth_micros) / 1e6)],
        );
        s
    }
}
