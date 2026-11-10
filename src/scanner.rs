//! Concurrent endpoint sweep. Generates candidate Cloudflare WARP `ip:port`
//! pairs and verifies each with a real WireGuard handshake (see `handshake`).
//! In a DPI-censored network most candidates time out; the ones that return a
//! valid handshake response are endpoints the censor isn't blocking.

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use rand_core::{OsRng, RngCore};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::handshake::{self, Verdict};
use crate::http_check::{self, CheckTarget};
use crate::tunnel;
use crate::warp::WarpAccount;

/// Which connectivity check to run through the tunnel after the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum CheckMode {
    /// GET http://www.cloudflare.com/cdn-cgi/trace, require `warp=on` in the body.
    Trace,
    /// GET http://www.gstatic.com/generate_204, require a 204 status.
    Generate204,
    /// Raw ICMP echo through the tunnel (see `tunnel::verify`).
    Ping,
}

/// Cloudflare /24 prefixes that carry WARP endpoints.
const V4_PREFIXES: &[[u8; 3]] = &[
    [162, 159, 192],
    [162, 159, 193],
    [162, 159, 195],
    [162, 159, 204],
    [188, 114, 96],
    [188, 114, 97],
    [188, 114, 98],
    [188, 114, 99],
];

/// Ports WARP is known to answer on. DPI often blocks 2408 specifically while
/// leaving many of the others open, so we sweep the whole list.
pub const WARP_PORTS: &[u16] = &[
    2408, 500, 1701, 4500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942,
    943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1843, 2371,
    2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319,
    8742, 8854, 8886,
];

#[derive(Clone)]
pub struct EndpointResult {
    pub addr: SocketAddr,
    pub probes: u32,
    pub successes: u32,
    /// Average handshake RTT over successful probes.
    pub avg_rtt: Duration,
    /// Average secondary-check RTT (ICMP ping in `Ping` mode, HTTP GET in
    /// `Trace`/`Generate204` mode); `None` in handshake-only mode.
    pub avg_check: Option<Duration>,
    /// Extra detail from the check, e.g. "warp=on" or "204 No Content".
    /// `None` in ping or handshake-only mode.
    pub detail: Option<String>,
}

impl EndpointResult {
    pub fn loss(&self) -> f64 {
        if self.probes == 0 {
            return 1.0;
        }
        1.0 - (self.successes as f64 / self.probes as f64)
    }

    /// Lower is better: the most meaningful RTT (the secondary check when we
    /// have it, else the handshake) in ms, plus a heavy penalty per lost probe.
    pub fn score(&self) -> f64 {
        let rtt = self.avg_check.unwrap_or(self.avg_rtt);
        rtt.as_secs_f64() * 1000.0 + self.loss() * 1000.0
    }
}

fn random_endpoint() -> SocketAddr {
    let p = V4_PREFIXES[(OsRng.next_u32() as usize) % V4_PREFIXES.len()];
    let host = (OsRng.next_u32() % 256) as u8;
    let port = WARP_PORTS[(OsRng.next_u32() as usize) % WARP_PORTS.len()];
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(p[0], p[1], p[2], host)), port)
}

/// Every IP in every prefix crossed with every port — the full known space.
fn all_endpoints() -> Vec<SocketAddr> {
    let mut v = Vec::with_capacity(V4_PREFIXES.len() * 256 * WARP_PORTS.len());
    for p in V4_PREFIXES {
        for host in 0..=255u8 {
            let ip = IpAddr::V4(Ipv4Addr::new(p[0], p[1], p[2], host));
            for &port in WARP_PORTS {
                v.push(SocketAddr::new(ip, port));
            }
        }
    }
    v
}

/// Sweep endpoints and return those that answered at least once, best-first.
///
/// `all = true` enumerates the entire known IP×port space; otherwise `count`
/// random candidates are sampled. `http_dest` must be `Some` when `check` is
/// `Trace`/`Generate204` and `handshake_only` is false (resolved once by the
/// caller, same as `ping_target`).
#[allow(clippy::too_many_arguments)]
pub async fn scan(
    acct: &WarpAccount,
    count: usize,
    all: bool,
    concurrency: usize,
    probes: u32,
    fake_packets: u32,
    timeout: Duration,
    handshake_only: bool,
    check: CheckMode,
    ping_target: Ipv4Addr,
    icmp_count: u32,
    http_dest: Option<Ipv4Addr>,
) -> Result<Vec<EndpointResult>> {
    let endpoints = if all {
        all_endpoints()
    } else {
        (0..count).map(|_| random_endpoint()).collect()
    };
    let total = endpoints.len();

    // Only meaningful beyond the handshake; resolved once up front so a bad
    // account address fails the whole scan rather than every probe.
    let src_v4 = if handshake_only {
        None
    } else {
        Some(acct.client_v4()?)
    };
    let http_target = match check {
        CheckMode::Trace => Some(CheckTarget::Trace),
        CheckMode::Generate204 => Some(CheckTarget::Generate204),
        CheckMode::Ping => None,
    };
    let reserved = acct.reserved;

    let sem = Arc::new(Semaphore::new(concurrency));
    let priv_key = Arc::new(acct.private_key.clone());
    let peer = Arc::new(acct.peer_public_key);
    let done = Arc::new(AtomicUsize::new(0));
    let found = Arc::new(AtomicUsize::new(0));
    let finished = Arc::new(AtomicBool::new(false));

    // Live progress line on stderr (kept separate from the result output).
    let ticker = {
        let done = done.clone();
        let found = found.clone();
        let finished = finished.clone();
        tokio::spawn(async move {
            while !finished.load(Ordering::Relaxed) {
                let d = done.load(Ordering::Relaxed);
                let f = found.load(Ordering::Relaxed);
                eprint!("\r  progress: {d}/{total}  ({f} found)        ");
                let _ = std::io::stderr().flush();
                tokio::time::sleep(Duration::from_millis(400)).await;
            }
        })
    };

    let mut set: JoinSet<EndpointResult> = JoinSet::new();
    for addr in endpoints {
        // Acquire the permit *before* spawning so at most `concurrency` probes
        // are live at once, bounding sockets and memory regardless of total.
        let permit = sem.clone().acquire_owned().await.unwrap();
        let priv_key = priv_key.clone();
        let peer = peer.clone();
        let done = done.clone();
        let found = found.clone();
        set.spawn(async move {
            let _permit = permit;
            let mut rtts = Vec::new();
            let mut checks = Vec::new();
            let mut detail: Option<String> = None;
            for _ in 0..probes {
                let idx = OsRng.next_u32();
                match src_v4 {
                    // Handshake-only mode: original behavior.
                    None => {
                        if let Ok(Verdict::Alive(d)) =
                            handshake::probe(&priv_key, &peer, addr, idx, fake_packets, timeout)
                                .await
                        {
                            rtts.push(d);
                        }
                    }
                    Some(src) => match check {
                        // Ping mode: a probe counts only if the ICMP round-trip
                        // through the tunnel succeeds.
                        CheckMode::Ping => {
                            if let Ok(tunnel::Verdict::Working {
                                handshake_rtt,
                                ping_rtt,
                                ..
                            }) = tunnel::verify(
                                &priv_key,
                                &peer,
                                src,
                                ping_target,
                                reserved,
                                addr,
                                idx,
                                fake_packets,
                                timeout,
                                icmp_count,
                            )
                            .await
                            {
                                rtts.push(handshake_rtt);
                                checks.push(ping_rtt);
                            }
                        }
                        // HTTP mode: a probe counts only if the real GET
                        // through the tunnel confirmed the expected result.
                        CheckMode::Trace | CheckMode::Generate204 => {
                            if let (Some(target), Some(dest)) = (http_target, http_dest) {
                                if let Ok(http_check::Verdict::Working {
                                    handshake_rtt,
                                    http_rtt,
                                    detail: d,
                                }) = http_check::verify(
                                    &priv_key,
                                    &peer,
                                    src,
                                    reserved,
                                    addr,
                                    dest,
                                    target,
                                    idx,
                                    fake_packets,
                                    timeout,
                                )
                                .await
                                {
                                    rtts.push(handshake_rtt);
                                    checks.push(http_rtt);
                                    detail = Some(d);
                                }
                            }
                        }
                    },
                }
            }
            let successes = rtts.len() as u32;
            let avg_rtt = if successes > 0 {
                rtts.iter().sum::<Duration>() / successes
            } else {
                Duration::ZERO
            };
            let avg_check = if !checks.is_empty() {
                Some(checks.iter().sum::<Duration>() / checks.len() as u32)
            } else {
                None
            };
            done.fetch_add(1, Ordering::Relaxed);
            if successes > 0 {
                found.fetch_add(1, Ordering::Relaxed);
            }
            EndpointResult {
                addr,
                probes,
                successes,
                avg_rtt,
                avg_check,
                detail,
            }
        });
    }

    let mut results = Vec::new();
    while let Some(r) = set.join_next().await {
        if let Ok(r) = r {
            if r.successes > 0 {
                results.push(r);
            }
        }
    }

    finished.store(true, Ordering::Relaxed);
    let _ = ticker.await;
    eprintln!(
        "\r  progress: {total}/{total}  ({} found)            ",
        results.len()
    );

    results.sort_by(|a, b| {
        a.score()
            .partial_cmp(&b.score())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_space_has_every_prefix_host_and_port() {
        assert_eq!(
            all_endpoints().len(),
            V4_PREFIXES.len() * 256 * WARP_PORTS.len()
        );
    }

    #[test]
    fn random_endpoints_stay_in_the_known_space() {
        for _ in 0..1_000 {
            let ep = random_endpoint();
            let SocketAddr::V4(v4) = ep else {
                panic!("expected an IPv4 endpoint, got {ep}");
            };
            let o = v4.ip().octets();
            assert!(V4_PREFIXES.iter().any(|p| p == &[o[0], o[1], o[2]]));
            assert!(WARP_PORTS.contains(&ep.port()));
        }
    }
}
