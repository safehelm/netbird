//! Sockets bound as Go binds them: ":443" is every address, IPv6 and IPv4 at
//! once, and IPv4 alone where the host has no IPv6.
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{SocketAddr, ToSocketAddrs};
use tracing::{info, warn};

/// The addresses to try for a Go listen address, in order
pub fn candidates(listen: &str) -> Result<Vec<SocketAddr>, String> {
    if let Some(port) = listen.strip_prefix(':') {
        let port: u16 = port.parse().map_err(|_| format!("invalid listen address {listen}"))?;
        return Ok(vec![SocketAddr::from(([0u16; 8], port)), SocketAddr::from(([0u8; 4], port))]);
    }
    let addrs: Vec<SocketAddr> =
        listen.to_socket_addrs().map_err(|e| format!("listen address {listen}: {e}"))?.collect();
    if addrs.is_empty() {
        return Err(format!("listen address {listen}: no address"));
    }
    Ok(addrs)
}

fn bind(listen: &str, ty: Type, proto: Protocol, prepare: impl Fn(&Socket)) -> Result<Socket, String> {
    let mut last = String::new();
    for addr in candidates(listen)? {
        let s = match Socket::new(Domain::for_address(addr), ty, Some(proto)) {
            Ok(s) => s,
            Err(e) => {
                last = format!("{addr}: {e}");
                continue;
            }
        };
        if addr.is_ipv6() && addr.ip().is_unspecified() {
            let _ = s.set_only_v6(false);
        }
        prepare(&s);
        match s.bind(&addr.into()) {
            Ok(()) => return Ok(s),
            Err(e) => last = format!("{addr}: {e}"),
        }
    }
    Err(last)
}

/// UDP for QUIC, its buffers asked for at `buffer` bytes (the kernel caps
/// them at net.core.rmem_max and wmem_max; quic-go asks for 7 MiB)
pub fn udp(listen: &str, buffer: usize) -> Result<std::net::UdpSocket, String> {
    let s = bind(listen, Type::DGRAM, Protocol::UDP, |s| {
        let _ = s.set_recv_buffer_size(buffer);
        let _ = s.set_send_buffer_size(buffer);
    })?;
    let (r, w) = (s.recv_buffer_size().unwrap_or(0), s.send_buffer_size().unwrap_or(0));
    if r < buffer || w < buffer {
        warn!("UDP buffers {r} and {w} bytes, asked for {buffer}: net.core.rmem_max and wmem_max cap them");
    } else {
        info!("UDP buffers {r} and {w} bytes");
    }
    s.set_nonblocking(true).map_err(|e| e.to_string())?;
    Ok(s.into())
}

pub fn tcp(listen: &str) -> Result<tokio::net::TcpListener, String> {
    let s = bind(listen, Type::STREAM, Protocol::TCP, |s| {
        let _ = s.set_reuse_address(true);
    })?;
    s.listen(1024).map_err(|e| e.to_string())?;
    s.set_nonblocking(true).map_err(|e| e.to_string())?;
    tokio::net::TcpListener::from_std(s.into()).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_listen_addresses() {
        assert_eq!(candidates(":443").unwrap(), ["[::]:443".parse().unwrap(), "0.0.0.0:443".parse().unwrap()]);
        assert_eq!(candidates("127.0.0.1:9000").unwrap(), ["127.0.0.1:9000".parse::<SocketAddr>().unwrap()]);
        assert!(candidates(":x").is_err());
    }
}
