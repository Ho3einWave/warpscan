//! Real WireGuard handshake probe, built on Cloudflare's own boringtun.
//!
//! We send a single Noise IKpsk2 *Handshake Initiation* to an endpoint and wait
//! for the *Handshake Response*. boringtun builds a cryptographically valid
//! initiation for us (correct mac1, AEAD, TAI64N, KDF chain) and validates the
//! reply, so a valid response means the endpoint genuinely speaks WireGuard and
//! accepted our registered key. Datagrams that are not a valid response (for
//! example a reply to one of the DPI-obfuscation packets) are ignored until the
//! deadline.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use rand_core::{OsRng, RngCore};
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// Outcome of a single handshake probe.
#[derive(Debug, Clone)]
pub enum Verdict {
    /// Endpoint returned a valid WireGuard handshake response; carries the RTT.
    Alive(Duration),
    /// No packet came back within the timeout.
    Timeout,
    /// A packet came back but boringtun rejected it (not a valid response to us).
    Rejected,
}

impl Verdict {
    pub fn rtt(&self) -> Option<Duration> {
        match self {
            Verdict::Alive(d) => Some(*d),
            _ => None,
        }
    }
}

/// Send one handshake initiation to `endpoint` and await the response.
///
/// `sender_index` should be unique per concurrent probe so responses can't be
/// confused; callers can just pass a random u32.
///
/// `fake_packets` mimics sing-box's obfuscation: that many junk UDP packets are
/// sent first on the same flow, so the first packet a DPI sees isn't a WireGuard
/// handshake. The WARP server silently drops the junk. Set to 0 for a plain probe.
pub async fn probe(
    my_private: &StaticSecret,
    peer_public: &PublicKey,
    endpoint: SocketAddr,
    sender_index: u32,
    fake_packets: u32,
    wait: Duration,
) -> Result<Verdict> {
    // Fresh one-shot tunnel per probe; we deliberately ignore boringtun's
    // internal timers since we only care about the first round trip.
    let mut tun = Tunn::new(
        my_private.clone(),
        *peer_public,
        None, // no preshared key
        None, // no persistent keepalive
        sender_index,
        None, // no rate limiter
    )
    .map_err(|e| anyhow!("Tunn::new failed: {e}"))?;

    let bind: SocketAddr = if endpoint.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(endpoint).await?;

    // Obfuscation: lead with junk packets so the flow's first packet isn't a
    // recognizable WireGuard handshake. Best-effort; the server drops these.
    for _ in 0..fake_packets {
        let len = 40 + (OsRng.next_u32() % 217) as usize; // 40..=256 bytes
        let mut junk = vec![0u8; len];
        OsRng.fill_bytes(&mut junk);
        let _ = sock.send(&junk).await;
    }

    let mut buf = [0u8; 2048];
    let init = match tun.format_handshake_initiation(&mut buf, false) {
        TunnResult::WriteToNetwork(pkt) => pkt,
        TunnResult::Err(e) => return Err(anyhow!("format_handshake_initiation: {e:?}")),
        _ => return Err(anyhow!("unexpected result building initiation")),
    };

    // Time only the real handshake, not the junk.
    let t0 = Instant::now();
    sock.send(init).await?;

    let mut rx = [0u8; 2048];
    let deadline = t0 + wait;
    let mut saw_invalid = false;
    loop {
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
        // A datagram too short to even hold a WireGuard message type can never
        // be a handshake response. Ignore it and keep waiting, otherwise a
        // host that echoes an empty UDP packet would be reported as ALIVE
        // (boringtun treats an empty datagram as "flush queued packets" and
        // returns Done).
        if n < 4 {
            saw_invalid = true;
            continue;
        }
        let rtt = t0.elapsed();

        let mut out = [0u8; 2048];
        match tun.decapsulate(None, &rx[..n], &mut out) {
            // A junk/obfuscation packet may get a reply from the endpoint
            // before the real handshake response; keep reading until the
            // deadline instead of failing the whole probe.
            TunnResult::Err(_) => {
                saw_invalid = true;
                continue;
            }
            // Only a Handshake Response (type 2) proves the peer completed our
            // handshake. A cookie reply (Done) or an initiation addressed to us
            // (WriteToNetwork) did not establish a session.
            TunnResult::WriteToNetwork(_) if rx[0] == 2 => return Ok(Verdict::Alive(rtt)),
            _ => {
                saw_invalid = true;
                continue;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_datagram_is_not_alive() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let (_n, peer) = server.recv_from(&mut buf).await.unwrap();
            server.send_to(&[], peer).await.unwrap();
        });

        let my_private = StaticSecret::random_from_rng(OsRng);
        let peer_secret = StaticSecret::random_from_rng(OsRng);
        let peer_public = PublicKey::from(&peer_secret);
        let verdict = probe(
            &my_private,
            &peer_public,
            addr,
            1,
            0,
            Duration::from_millis(250),
        )
        .await
        .unwrap();
        assert!(matches!(verdict, Verdict::Rejected), "got {verdict:?}");
    }

    #[tokio::test]
    async fn real_handshake_response_is_alive() {
        let server_private = StaticSecret::random_from_rng(OsRng);
        let server_public = PublicKey::from(&server_private);
        let client_private = StaticSecret::random_from_rng(OsRng);
        let client_public = PublicKey::from(&client_private);

        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut tun = Tunn::new(server_private, client_public, None, None, 42, None).unwrap();
            let mut buf = [0u8; 2048];
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            // WARP can answer an obfuscation/junk packet before the real
            // handshake response; the probe must skip it.
            server.send_to(&[0xcf; 16], peer).await.unwrap();
            let mut out = [0u8; 2048];
            match tun.decapsulate(None, &buf[..n], &mut out) {
                TunnResult::WriteToNetwork(response) => {
                    server.send_to(response, peer).await.unwrap();
                }
                other => panic!("expected handshake response, got {other:?}"),
            }
        });

        let verdict = probe(
            &client_private,
            &server_public,
            addr,
            2,
            0,
            Duration::from_millis(1000),
        )
        .await
        .unwrap();
        assert!(matches!(verdict, Verdict::Alive(_)), "got {verdict:?}");
    }
}
