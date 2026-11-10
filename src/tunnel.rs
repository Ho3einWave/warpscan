//! End-to-end tunnel verification: not just "does this endpoint speak
//! WireGuard?" but "does traffic actually reach the internet through it?".
//!
//! After completing the handshake (as in `handshake`), we build a real ICMP
//! echo request *inside* the tunnel, encrypt it with boringtun's `encapsulate`,
//! send it on the same UDP socket, and wait for the encrypted echo reply. A
//! valid reply means the WARP endpoint routed our packet to the target
//! (1.1.1.1 by default) and back — genuine connectivity, no TUN interface.
//!
//! Two WARP quirks matter here:
//!   * The 3 "reserved" WireGuard header bytes must carry the account's
//!     client_id on data packets, so we patch every outgoing packet.
//!   * Our inner source address is the IPv4 the registration assigned us.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use rand_core::{OsRng, RngCore};
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// Outcome of an end-to-end tunnel probe.
#[derive(Debug, Clone)]
pub enum Verdict {
    /// Handshake completed *and* at least one ICMP echo made the full round
    /// trip. `ping_rtt` is the average over the echoes that got a reply.
    Working {
        handshake_rtt: Duration,
        ping_rtt: Duration,
        ping_sent: u32,
        ping_received: u32,
    },
    /// Handshake completed but no echo reply came back: the endpoint speaks
    /// WireGuard but did not carry our traffic to the target.
    HandshakeOnly { handshake_rtt: Duration },
    /// No handshake response within the timeout.
    Timeout,
    /// A packet came back but boringtun rejected it as not a valid response.
    Rejected,
}

/// Overwrite the 3 WireGuard "reserved" bytes with the WARP client_id. Every
/// packet WARP's data plane accepts must carry these; boringtun writes zeros.
fn set_reserved(pkt: &mut [u8], reserved: [u8; 3]) {
    if pkt.len() >= 4 {
        pkt[1] = reserved[0];
        pkt[2] = reserved[1];
        pkt[3] = reserved[2];
    }
}

/// Zero the reserved bytes on an incoming packet. WARP echoes the client_id
/// there, but boringtun folds byte 0 + the reserved bytes into one u32 when it
/// classifies a packet, so anything non-zero reads as an invalid message type.
fn clear_reserved(pkt: &mut [u8]) {
    if pkt.len() >= 4 {
        pkt[1] = 0;
        pkt[2] = 0;
        pkt[3] = 0;
    }
}

/// Standard internet 16-bit one's-complement checksum (RFC 1071).
fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build an IPv4 + ICMP echo-request packet (the inner, plaintext packet that
/// travels through the tunnel).
fn build_icmp_echo(src: Ipv4Addr, dst: Ipv4Addr, ident: u16, seq: u16) -> Vec<u8> {
    // A small fixed payload so the reply is unambiguous.
    let payload: [u8; 16] = *b"warpscan-ping\0\0\0";

    let mut icmp = Vec::with_capacity(8 + payload.len());
    icmp.extend_from_slice(&[8, 0]); // type 8 (echo request), code 0
    icmp.extend_from_slice(&[0, 0]); // checksum placeholder
    icmp.extend_from_slice(&ident.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(&payload);
    let c = checksum(&icmp);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());

    let total_len = 20 + icmp.len();
    let mut ip = Vec::with_capacity(total_len);
    ip.push(0x45); // version 4, IHL 5 (no options)
    ip.push(0x00); // DSCP/ECN
    ip.extend_from_slice(&(total_len as u16).to_be_bytes());
    ip.extend_from_slice(&ident.to_be_bytes()); // identification
    ip.extend_from_slice(&0x4000u16.to_be_bytes()); // flags: Don't Fragment
    ip.push(64); // TTL
    ip.push(1); // protocol: ICMP
    ip.extend_from_slice(&[0, 0]); // header checksum placeholder
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    let hc = checksum(&ip);
    ip[10..12].copy_from_slice(&hc.to_be_bytes());

    ip.extend_from_slice(&icmp);
    ip
}

/// Is `pkt` (a decrypted inner IPv4 packet) the ICMP echo reply we sent?
fn is_our_echo_reply(pkt: &[u8], ident: u16, seq: u16) -> bool {
    if pkt.len() < 20 || (pkt[0] >> 4) != 4 {
        return false;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if pkt[9] != 1 || pkt.len() < ihl + 8 {
        return false; // not ICMP, or truncated
    }
    let icmp = &pkt[ihl..];
    icmp[0] == 0 // echo reply
        && u16::from_be_bytes([icmp[4], icmp[5]]) == ident
        && u16::from_be_bytes([icmp[6], icmp[7]]) == seq
}

/// Handshake with `endpoint`, then send `icmp_count` ICMP echoes to `target`
/// through the tunnel and wait for each reply in turn. `wait` bounds the
/// handshake and each individual echo separately.
#[allow(clippy::too_many_arguments)]
pub async fn verify(
    my_private: &StaticSecret,
    peer_public: &PublicKey,
    src_v4: Ipv4Addr,
    target: Ipv4Addr,
    reserved: [u8; 3],
    endpoint: SocketAddr,
    sender_index: u32,
    fake_packets: u32,
    wait: Duration,
    icmp_count: u32,
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
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(endpoint).await?;

    // DPI obfuscation: junk packets first, same as the handshake-only probe.
    for _ in 0..fake_packets {
        let len = 40 + (OsRng.next_u32() % 217) as usize;
        let mut junk = vec![0u8; len];
        OsRng.fill_bytes(&mut junk);
        let _ = sock.send(&junk).await;
    }

    // ---- Phase 1: handshake ----
    let mut buf = [0u8; 2048];
    let init = match tun.format_handshake_initiation(&mut buf, false) {
        TunnResult::WriteToNetwork(pkt) => pkt,
        TunnResult::Err(e) => return Err(anyhow!("format_handshake_initiation: {e:?}")),
        _ => return Err(anyhow!("unexpected result building initiation")),
    };
    set_reserved(init, reserved);

    let t0 = Instant::now();
    sock.send(init).await?;

    let mut rx = [0u8; 2048];
    let mut out = [0u8; 2048];
    let deadline = t0 + wait;
    let mut saw_invalid = false;
    let handshake_rtt = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(if saw_invalid {
                Verdict::Rejected
            } else {
                Verdict::Timeout
            });
        }
        let n = match timeout(remaining, sock.recv(&mut rx)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                return Ok(if saw_invalid {
                    Verdict::Rejected
                } else {
                    Verdict::Timeout
                })
            }
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
                // Keepalive that finalizes the session; send it so WARP
                // considers the tunnel up before we push data.
                set_reserved(pkt, reserved);
                let _ = sock.send(pkt).await;
                break rtt;
            }
            _ => {
                saw_invalid = true;
                continue;
            }
        }
    };
    // Flush any packets boringtun queued during the handshake.
    drain(&mut tun, &sock, reserved).await;

    // ---- Phase 2: ICMP echoes through the tunnel ----
    let ident = (sender_index & 0xffff) as u16;
    let icmp_count = icmp_count.max(1);
    let mut rtts: Vec<Duration> = Vec::new();

    for seq in 1..=icmp_count {
        let echo = build_icmp_echo(src_v4, target, ident, seq as u16);
        let mut enc = [0u8; 2048];
        match tun.encapsulate(&echo, &mut enc) {
            TunnResult::WriteToNetwork(pkt) => {
                set_reserved(pkt, reserved);
                let p0 = Instant::now();
                sock.send(pkt).await?;

                // Read until we see this echo's reply or it times out. Other
                // traffic (keepalives, cookie replies) is handled and ignored.
                let deadline = tokio::time::Instant::now() + wait;
                loop {
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    if remaining.is_zero() {
                        break; // this echo got no reply; try the next one
                    }
                    let n = match timeout(remaining, sock.recv(&mut rx)).await {
                        Ok(Ok(n)) => n,
                        Ok(Err(_)) => continue,
                        Err(_) => break,
                    };
                    clear_reserved(&mut rx[..n]);
                    match tun.decapsulate(None, &rx[..n], &mut out) {
                        TunnResult::WriteToTunnelV4(pkt, _) => {
                            if is_our_echo_reply(pkt, ident, seq as u16) {
                                rtts.push(p0.elapsed());
                                break;
                            }
                        }
                        TunnResult::WriteToNetwork(pkt) => {
                            set_reserved(pkt, reserved);
                            let _ = sock.send(pkt).await;
                            drain(&mut tun, &sock, reserved).await;
                        }
                        _ => {}
                    }
                }
            }
            // encapsulate falling back to a handshake means the session
            // wasn't established; nothing more to try.
            _ => return Ok(Verdict::HandshakeOnly { handshake_rtt }),
        }
    }

    if rtts.is_empty() {
        Ok(Verdict::HandshakeOnly { handshake_rtt })
    } else {
        let ping_received = rtts.len() as u32;
        let ping_rtt = rtts.iter().sum::<Duration>() / ping_received;
        Ok(Verdict::Working {
            handshake_rtt,
            ping_rtt,
            ping_sent: icmp_count,
            ping_received,
        })
    }
}

/// Send every packet boringtun has queued, until it reports the queue drained.
async fn drain(tun: &mut Tunn, sock: &UdpSocket, reserved: [u8; 3]) {
    let mut out = [0u8; 2048];
    while let TunnResult::WriteToNetwork(pkt) = tun.decapsulate(None, &[], &mut out) {
        set_reserved(pkt, reserved);
        let _ = sock.send(pkt).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_of_empty_buffer_is_all_ones() {
        assert_eq!(checksum(&[]), 0xffff);
    }

    #[test]
    fn built_icmp_echo_has_valid_headers_and_is_recognized() {
        let src = Ipv4Addr::new(172, 16, 0, 2);
        let dst = Ipv4Addr::new(1, 1, 1, 1);
        let mut pkt = build_icmp_echo(src, dst, 0x1234, 7);

        // A correct IPv4 header checksum makes the checksum over the whole
        // header evaluate to zero.
        assert_eq!(checksum(&pkt[..20]), 0);
        assert_eq!(&pkt[12..16], &src.octets());
        assert_eq!(&pkt[16..20], &dst.octets());
        assert_eq!(pkt[9], 1, "protocol should be ICMP");

        // The helper wants an echo *reply*; the built packet is a request.
        assert!(!is_our_echo_reply(&pkt, 0x1234, 7));
        pkt[20] = 0; // flip ICMP type 8 (request) -> 0 (reply)
        assert!(is_our_echo_reply(&pkt, 0x1234, 7));
        assert!(!is_our_echo_reply(&pkt, 0x1234, 8));
        assert!(!is_our_echo_reply(&pkt, 0x9999, 7));
    }

    #[test]
    fn truncated_icmp_packet_is_not_a_reply() {
        let pkt = [0x45u8; 12];
        assert!(!is_our_echo_reply(&pkt, 0, 0));
    }
}
