//! Real HTTP connectivity check through the WARP tunnel: not just a raw ICMP
//! echo (see `tunnel`), but an actual TCP handshake and HTTP GET. boringtun
//! only speaks WireGuard - it hands us plaintext IP packets to send and
//! decrypts the ones we receive, but has no notion of TCP - so a minimal
//! userspace TCP/IP stack (`smoltcp`) is bridged on top of it here, the same
//! role gVisor's netstack plays in the Go `warp-plus` project.
//!
//! Both check targets answer on plain HTTP (no TLS), so nothing beyond TCP is
//! needed:
//!   * `http://www.cloudflare.com/cdn-cgi/trace` - the body contains
//!     `warp=on` only when Cloudflare itself recognizes the request as
//!     genuinely arriving through WARP. This is the strongest signal we can
//!     get and is the default check.
//!   * `http://www.gstatic.com/generate_204` - a bare 204, useful as a
//!     lighter/faster "is anything routing at all" check.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant as StdInstant};

use anyhow::{anyhow, Result};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use rand_core::{OsRng, RngCore};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

/// Which HTTP endpoint to check through the tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckTarget {
    Trace,
    Generate204,
}

impl CheckTarget {
    pub fn host(self) -> &'static str {
        match self {
            CheckTarget::Trace => "www.cloudflare.com",
            CheckTarget::Generate204 => "www.gstatic.com",
        }
    }

    pub fn path(self) -> &'static str {
        match self {
            CheckTarget::Trace => "/cdn-cgi/trace",
            CheckTarget::Generate204 => "/generate_204",
        }
    }
}

/// Outcome of an HTTP-over-tunnel probe.
#[derive(Debug, Clone)]
pub enum Verdict {
    /// Handshake completed and the HTTP check confirmed the expected result
    /// (`warp=on` for Trace, a 204 status for Generate204).
    Working {
        handshake_rtt: Duration,
        http_rtt: Duration,
        detail: String,
    },
    /// Handshake completed but the HTTP check never confirmed the expected
    /// result (wrong status, `warp=off`/missing, or no response before the
    /// deadline): real WireGuard, but not confirmed as genuinely WARP-routed.
    HandshakeOnly { handshake_rtt: Duration },
    /// No handshake response within the timeout.
    Timeout,
    /// A packet came back but boringtun rejected it as not a valid response.
    Rejected,
}

/// Overwrite the 3 WireGuard "reserved" bytes with the WARP client_id, as
/// required on every packet WARP's data plane accepts (see `tunnel.rs`).
fn set_reserved(pkt: &mut [u8], reserved: [u8; 3]) {
    if pkt.len() >= 4 {
        pkt[1] = reserved[0];
        pkt[2] = reserved[1];
        pkt[3] = reserved[2];
    }
}

/// Zero the reserved bytes on an incoming packet before boringtun classifies
/// it (see `tunnel.rs`).
fn clear_reserved(pkt: &mut [u8]) {
    if pkt.len() >= 4 {
        pkt[1] = 0;
        pkt[2] = 0;
        pkt[3] = 0;
    }
}

/// A boringtun-backed smoltcp [`Device`] operating in `Medium::Ip` (no
/// Ethernet/ARP - same as any point-to-point tunnel device). It owns the
/// `Tunn` session and the UDP socket outright so both the transmit path
/// (`encapsulate`) and the receive path (`pump` + `decapsulate`) can touch
/// them without any aliasing conflicts.
struct WgDevice {
    tun: Tunn,
    sock: UdpSocket,
    reserved: [u8; 3],
    /// A plaintext IP packet decapsulated by `pump`, waiting for smoltcp to
    /// pick it up on the next `receive()`.
    rx: Option<Vec<u8>>,
}

impl WgDevice {
    fn set_read_timeout(&self, d: Duration) -> std::io::Result<()> {
        self.sock.set_read_timeout(Some(d))
    }

    /// Try to read one UDP datagram (bounded by the socket's current read
    /// timeout) and decapsulate it. A decrypted data packet is stashed for
    /// the next `receive()`; WireGuard control traffic (handshake
    /// finalization, keepalives, cookie replies) is sent back immediately.
    fn pump(&mut self) -> Result<()> {
        let mut buf = [0u8; 2048];
        match self.sock.recv(&mut buf) {
            Ok(n) => {
                clear_reserved(&mut buf[..n]);
                let mut out = [0u8; 2048];
                match self.tun.decapsulate(None, &buf[..n], &mut out) {
                    TunnResult::WriteToTunnelV4(pkt, _) => self.rx = Some(pkt.to_vec()),
                    TunnResult::WriteToNetwork(pkt) => {
                        set_reserved(pkt, self.reserved);
                        let _ = self.sock.send(pkt);
                        self.drain();
                    }
                    _ => {}
                }
                Ok(())
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Send every packet boringtun has queued, until it reports the queue
    /// drained (sync counterpart of `tunnel::drain`).
    fn drain(&mut self) {
        let mut out = [0u8; 2048];
        while let TunnResult::WriteToNetwork(pkt) = self.tun.decapsulate(None, &[], &mut out) {
            set_reserved(pkt, self.reserved);
            let _ = self.sock.send(pkt);
        }
    }
}

struct WgRxToken(Vec<u8>);

impl RxToken for WgRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct WgTxToken<'a> {
    tun: &'a mut Tunn,
    sock: &'a UdpSocket,
    reserved: [u8; 3],
}

impl<'a> TxToken for WgTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        let mut out = [0u8; 2048];
        if let TunnResult::WriteToNetwork(pkt) = self.tun.encapsulate(&buf, &mut out) {
            set_reserved(pkt, self.reserved);
            let _ = self.sock.send(pkt);
        }
        result
    }
}

impl Device for WgDevice {
    type RxToken<'a>
        = WgRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = WgTxToken<'a>
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx.take()?;
        Some((
            WgRxToken(pkt),
            WgTxToken {
                tun: &mut self.tun,
                sock: &self.sock,
                reserved: self.reserved,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(WgTxToken {
            tun: &mut self.tun,
            sock: &self.sock,
            reserved: self.reserved,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1400;
        caps.medium = Medium::Ip;
        caps
    }
}

/// Index of the byte right after the first `\r\n\r\n` (end of HTTP headers),
/// if the buffer contains one yet.
fn header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn content_length(head: &str) -> Option<usize> {
    head.lines().find_map(|line| {
        let lower = line.to_ascii_lowercase();
        lower.strip_prefix("content-length:")?.trim().parse().ok()
    })
}

/// Whether `buf` holds a full HTTP response: headers plus, if a
/// `Content-Length` was given, that many body bytes. Responses without a
/// `Content-Length` (e.g. a bare 204) are considered complete as soon as the
/// headers are in.
fn response_complete(buf: &[u8]) -> bool {
    match header_end(buf) {
        Some(end) => {
            let head = String::from_utf8_lossy(&buf[..end]);
            match content_length(&head) {
                Some(len) => buf.len() >= end + len,
                None => true,
            }
        }
        None => false,
    }
}

/// Check whether a (possibly still-incomplete) response satisfies `target`'s
/// expected condition.
fn evaluate(buf: &[u8], target: CheckTarget) -> Option<String> {
    let text = String::from_utf8_lossy(buf);
    let status_line = text.lines().next().unwrap_or("");
    match target {
        CheckTarget::Trace => {
            if status_line.contains(" 200 ") && text.contains("warp=on") {
                Some("warp=on".to_string())
            } else {
                None
            }
        }
        CheckTarget::Generate204 => {
            if status_line.contains(" 204 ") {
                Some("204 No Content".to_string())
            } else {
                None
            }
        }
    }
}

/// Handshake with `endpoint`, then perform a real TCP connection and HTTP GET
/// to `target` (at `dest_ip`, port 80) through the tunnel.
#[allow(clippy::too_many_arguments)]
pub async fn verify(
    my_private: &StaticSecret,
    peer_public: &PublicKey,
    src_v4: Ipv4Addr,
    reserved: [u8; 3],
    endpoint: SocketAddr,
    dest_ip: Ipv4Addr,
    target: CheckTarget,
    sender_index: u32,
    fake_packets: u32,
    wait: Duration,
) -> Result<Verdict> {
    let my_private = my_private.clone();
    let peer_public = *peer_public;
    tokio::task::spawn_blocking(move || {
        verify_blocking(
            &my_private,
            &peer_public,
            src_v4,
            reserved,
            endpoint,
            dest_ip,
            target,
            sender_index,
            fake_packets,
            wait,
        )
    })
    .await
    .map_err(|e| anyhow!("http check task panicked: {e}"))?
}

#[allow(clippy::too_many_arguments)]
fn verify_blocking(
    my_private: &StaticSecret,
    peer_public: &PublicKey,
    src_v4: Ipv4Addr,
    reserved: [u8; 3],
    endpoint: SocketAddr,
    dest_ip: Ipv4Addr,
    target: CheckTarget,
    sender_index: u32,
    fake_packets: u32,
    wait: Duration,
) -> Result<Verdict> {
    let mut tun = Tunn::new(
        my_private.clone(),
        *peer_public,
        None,
        None,
        sender_index,
        None,
    )
    .map_err(|e| anyhow!("Tunn::new failed: {e}"))?;

    let bind: SocketAddr = if endpoint.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let sock = UdpSocket::bind(bind)?;
    sock.connect(endpoint)?;

    for _ in 0..fake_packets {
        let len = 40 + (OsRng.next_u32() % 217) as usize;
        let mut junk = vec![0u8; len];
        OsRng.fill_bytes(&mut junk);
        let _ = sock.send(&junk);
    }

    // ---- Phase 1: handshake ----
    let mut buf = [0u8; 2048];
    let init = match tun.format_handshake_initiation(&mut buf, false) {
        TunnResult::WriteToNetwork(pkt) => pkt,
        TunnResult::Err(e) => return Err(anyhow!("format_handshake_initiation: {e:?}")),
        _ => return Err(anyhow!("unexpected result building initiation")),
    };
    set_reserved(init, reserved);

    let t0 = StdInstant::now();
    sock.send(init)?;

    let mut rx = [0u8; 2048];
    let mut out = [0u8; 2048];
    let deadline = t0 + wait;
    let mut saw_invalid = false;
    let handshake_rtt = loop {
        let remaining = deadline.saturating_duration_since(StdInstant::now());
        if remaining.is_zero() {
            return Ok(if saw_invalid {
                Verdict::Rejected
            } else {
                Verdict::Timeout
            });
        }
        // set_read_timeout rejects a zero duration; 1 ms is close enough to
        // the deadline.
        sock.set_read_timeout(Some(remaining.max(Duration::from_millis(1))))?;
        let n = match sock.recv(&mut rx) {
            Ok(n) => n,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Ok(if saw_invalid {
                    Verdict::Rejected
                } else {
                    Verdict::Timeout
                })
            }
            Err(e) => return Err(e.into()),
        };
        if n < 4 {
            saw_invalid = true;
            continue;
        }
        clear_reserved(&mut rx[..n]);
        match tun.decapsulate(None, &rx[..n], &mut out) {
            // Junk/obfuscation packets can get a non-WireGuard reply before
            // the real handshake response; ignore it and keep waiting.
            TunnResult::Err(_) => {
                saw_invalid = true;
                continue;
            }
            // Only a Handshake Response (type 2) establishes the session.
            TunnResult::WriteToNetwork(pkt) if rx[0] == 2 => {
                let rtt = t0.elapsed();
                set_reserved(pkt, reserved);
                let _ = sock.send(pkt);
                break rtt;
            }
            _ => {
                saw_invalid = true;
                continue;
            }
        }
    };
    // Flush anything boringtun queued during the handshake (mirrors tunnel::drain).
    while let TunnResult::WriteToNetwork(pkt) = tun.decapsulate(None, &[], &mut out) {
        set_reserved(pkt, reserved);
        let _ = sock.send(pkt);
    }

    // ---- Phase 2: TCP + HTTP over smoltcp ----
    let mut device = WgDevice {
        tun,
        sock,
        reserved,
        rx: None,
    };

    let config = Config::new(HardwareAddress::Ip);
    let mut iface = Interface::new(config, &mut device, SmolInstant::now());
    iface.update_ip_addrs(|addrs| {
        let o = src_v4.octets();
        let _ = addrs.push(IpCidr::new(IpAddress::v4(o[0], o[1], o[2], o[3]), 32));
    });
    // Medium::Ip skips ARP/neighbor resolution entirely, but a route lookup
    // still has to succeed for an off-subnet destination to be dispatched at
    // all; the gateway address itself is never used for Ip-medium routing.
    iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Addr::new(0, 0, 0, 1))
        .map_err(|e| anyhow!("failed to add default route: {e:?}"))?;

    let rx_buffer = tcp::SocketBuffer::new(vec![0u8; 4096]);
    let tx_buffer = tcp::SocketBuffer::new(vec![0u8; 4096]);
    let mut sockets = SocketSet::new(Vec::new());
    let handle = sockets.add(tcp::Socket::new(rx_buffer, tx_buffer));

    let dest_octets = dest_ip.octets();
    let dest = IpAddress::v4(
        dest_octets[0],
        dest_octets[1],
        dest_octets[2],
        dest_octets[3],
    );
    let local_port = 20000u16.wrapping_add((sender_index % 20000) as u16).max(1);
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: warpscan\r\nConnection: close\r\n\r\n",
        target.path(),
        target.host()
    );

    let mut connected = false;
    let mut sent = 0usize;
    let mut response = Vec::new();
    let deadline = StdInstant::now() + wait;
    let http_t0 = StdInstant::now();

    loop {
        if StdInstant::now() >= deadline {
            return Ok(Verdict::HandshakeOnly { handshake_rtt });
        }

        let poll_delay = iface
            .poll_delay(SmolInstant::now(), &sockets)
            .map(|d| Duration::from_micros(d.total_micros()))
            .unwrap_or(Duration::from_millis(20));
        let remaining = deadline.saturating_duration_since(StdInstant::now());
        let recv_timeout = poll_delay
            .min(remaining)
            .min(Duration::from_millis(50))
            .max(Duration::from_millis(1));
        device.set_read_timeout(recv_timeout)?;
        device.pump()?;

        iface.poll(SmolInstant::now(), &mut device, &mut sockets);

        let cx = iface.context();
        let socket = sockets.get_mut::<tcp::Socket>(handle);
        if !connected {
            socket
                .connect(cx, (dest, 80), local_port)
                .map_err(|e| anyhow!("tcp connect failed: {e:?}"))?;
            connected = true;
        }

        if socket.can_send() && sent < request.len() {
            // send_slice returns how many bytes were queued, which can be less
            // than the whole request; keep the remainder for the next poll.
            if let Ok(n) = socket.send_slice(&request.as_bytes()[sent..]) {
                sent += n;
            }
        }

        if socket.can_recv() {
            let mut tmp = [0u8; 2048];
            if let Ok(n) = socket.recv_slice(&mut tmp) {
                response.extend_from_slice(&tmp[..n]);
            }
        }

        let closed = sent == request.len() && socket.state() == tcp::State::Closed;

        if (!response.is_empty() && response_complete(&response)) || closed {
            let http_rtt = http_t0.elapsed();
            return Ok(match evaluate(&response, target) {
                Some(detail) => Verdict::Working {
                    handshake_rtt,
                    http_rtt,
                    detail,
                },
                None => Verdict::HandshakeOnly { handshake_rtt },
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_end_finds_terminator() {
        let buf = b"HTTP/1.1 200 OK\r\nA: b\r\n\r\nbody";
        assert_eq!(header_end(buf), Some(25));
        assert_eq!(header_end(b"HTTP/1.1 200 OK\r\n"), None);
    }

    #[test]
    fn response_complete_respects_content_length() {
        assert!(!response_complete(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc"
        ));
        assert!(response_complete(
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc"
        ));
        assert!(response_complete(b"HTTP/1.1 204 No Content\r\n\r\n"));
    }

    #[test]
    fn evaluate_trace_requires_200_and_warp_on() {
        assert_eq!(
            evaluate(b"HTTP/1.1 200 OK\r\n\r\nwarp=on\n", CheckTarget::Trace),
            Some("warp=on".to_string())
        );
        assert_eq!(
            evaluate(b"HTTP/1.1 200 OK\r\n\r\nwarp=off\n", CheckTarget::Trace),
            None
        );
        assert_eq!(
            evaluate(
                b"HTTP/1.1 403 Forbidden\r\n\r\nwarp=on\n",
                CheckTarget::Trace
            ),
            None
        );
    }

    #[test]
    fn evaluate_generate204_requires_204() {
        assert_eq!(
            evaluate(b"HTTP/1.1 204 No Content\r\n\r\n", CheckTarget::Generate204),
            Some("204 No Content".to_string())
        );
        assert_eq!(
            evaluate(b"HTTP/1.1 200 OK\r\n\r\n", CheckTarget::Generate204),
            None
        );
    }
}
