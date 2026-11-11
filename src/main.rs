mod handshake;
mod http_check;
mod masque_scan;
mod scanner;
mod throughput;
mod tunnel;
mod warp;

use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use clap::{Parser, Subcommand};
use rand_core::{OsRng, RngCore};

use scanner::CheckMode;

#[derive(Parser)]
#[command(
    name = "warpscan",
    about = "Cloudflare WARP endpoint scanner with a real WireGuard handshake test"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    /// Path to the saved WARP account (created on first run, reused after).
    #[arg(long, global = true, default_value = "warp-account.json")]
    account: PathBuf,
    /// Ignore any saved account and register a fresh one (overwrites the file).
    #[arg(long, global = true, default_value_t = false)]
    new: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Register a WARP account and probe a single endpoint (smoke test).
    Probe {
        /// Endpoint as host:port, e.g. 162.159.192.1:2408
        endpoint: String,
        /// Junk packets sent before the handshake to evade DPI (0 = plain).
        #[arg(long, default_value_t = 8)]
        fake: u32,
        /// Handshake (and check) timeout in milliseconds.
        #[arg(long, default_value_t = 1500)]
        timeout_ms: u64,
        /// Only verify the WireGuard handshake; skip the end-to-end check.
        #[arg(long, default_value_t = false)]
        handshake_only: bool,
        /// Connectivity check to run through the tunnel after the handshake.
        #[arg(long, value_enum, default_value_t = CheckMode::Trace)]
        check: CheckMode,
        /// Target pinged through the tunnel when --check ping.
        #[arg(long, default_value_t = Ipv4Addr::new(1, 1, 1, 1))]
        ping_target: Ipv4Addr,
        /// ICMP echoes sent within the session when --check ping.
        #[arg(long, default_value_t = 3)]
        icmp_count: u32,
    },
    /// Sweep WARP endpoints and report those that pass a real handshake.
    Scan {
        /// Exhaustively scan every IP×port in the known space (ignores --count).
        #[arg(long, default_value_t = false)]
        all: bool,
        /// Number of random candidate endpoints to try (when not using --all).
        #[arg(long, default_value_t = 400)]
        count: usize,
        /// Maximum concurrent probes.
        #[arg(long, default_value_t = 100)]
        concurrency: usize,
        /// Probes per endpoint (more = better loss/jitter estimate, slower).
        #[arg(long, default_value_t = 1)]
        probes: u32,
        /// Junk packets sent before each handshake to evade DPI (0 = plain).
        #[arg(long, default_value_t = 8)]
        fake: u32,
        /// Handshake (and check) timeout in milliseconds.
        #[arg(long, default_value_t = 1500)]
        timeout_ms: u64,
        /// How many of the best results to print.
        #[arg(long, default_value_t = 10)]
        top: usize,
        /// Only require a WireGuard handshake; skip the end-to-end check.
        #[arg(long, default_value_t = false)]
        handshake_only: bool,
        /// Connectivity check to run through the tunnel after the handshake.
        #[arg(long, value_enum, default_value_t = CheckMode::Trace)]
        check: CheckMode,
        /// Target pinged through the tunnel when --check ping.
        #[arg(long, default_value_t = Ipv4Addr::new(1, 1, 1, 1))]
        ping_target: Ipv4Addr,
        /// ICMP echoes sent within each session when --check ping.
        #[arg(long, default_value_t = 3)]
        icmp_count: u32,
        #[command(flatten)]
        throughput: throughput::ThroughputArgs,
    },
    /// Rank MASQUE endpoints (162.159.198.0/24 and 2606:4700:103::/64) by
    /// data-plane throughput through warpeer.
    Masque(masque_scan::MasqueArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let account = cli.account;
    let new = cli.new;
    match cli.cmd {
        Cmd::Probe {
            endpoint,
            fake,
            timeout_ms,
            handshake_only,
            check,
            ping_target,
            icmp_count,
        } => {
            probe_cmd(
                &account,
                new,
                &endpoint,
                fake,
                timeout_ms,
                handshake_only,
                check,
                ping_target,
                icmp_count,
            )
            .await
        }
        Cmd::Scan {
            all,
            count,
            concurrency,
            probes,
            fake,
            timeout_ms,
            top,
            handshake_only,
            check,
            ping_target,
            icmp_count,
            throughput,
        } => {
            scan_cmd(
                &account,
                new,
                all,
                count,
                concurrency,
                probes,
                fake,
                timeout_ms,
                top,
                handshake_only,
                check,
                ping_target,
                icmp_count,
                throughput,
            )
            .await
        }
        Cmd::Masque(args) => masque_scan::run(args).await,
    }
}

/// Load the saved account or register+save a fresh one, printing what happened.
async fn obtain_account(account: &std::path::Path, new: bool) -> Result<warp::WarpAccount> {
    let (acct, fresh) = warp::load_or_register(account, new).await?;
    if fresh {
        eprintln!(
            "Registered a new WARP account (reserved={:?}); saved to {}",
            acct.reserved,
            account.display()
        );
    } else {
        eprintln!(
            "Reusing saved WARP account from {} (reserved={:?})",
            account.display(),
            acct.reserved
        );
    }
    Ok(acct)
}

/// Resolve an HTTP check target's host to an IPv4 address once, so a bad DNS
/// result fails fast instead of failing every candidate endpoint. `None` for
/// `CheckMode::Ping`, which doesn't need it.
async fn resolve_http_dest(check: CheckMode) -> Result<Option<Ipv4Addr>> {
    let target = match check {
        CheckMode::Trace => http_check::CheckTarget::Trace,
        CheckMode::Generate204 => http_check::CheckTarget::Generate204,
        CheckMode::Ping => return Ok(None),
    };
    let host = target.host();
    let addr = tokio::net::lookup_host((host, 80))
        .await?
        .find_map(|a| match a {
            SocketAddr::V4(v4) => Some(*v4.ip()),
            _ => None,
        })
        .ok_or_else(|| anyhow!("could not resolve {host} to an IPv4 address"))?;
    Ok(Some(addr))
}

#[allow(clippy::too_many_arguments)]
async fn scan_cmd(
    account: &std::path::Path,
    new: bool,
    all: bool,
    count: usize,
    concurrency: usize,
    probes: u32,
    fake: u32,
    timeout_ms: u64,
    top: usize,
    handshake_only: bool,
    check: CheckMode,
    ping_target: Ipv4Addr,
    icmp_count: u32,
    throughput_args: throughput::ThroughputArgs,
) -> Result<()> {
    if concurrency == 0 {
        bail!("--concurrency must be at least 1");
    }
    if probes == 0 {
        bail!("--probes must be at least 1");
    }
    if timeout_ms == 0 {
        bail!("--timeout-ms must be at least 1");
    }
    if !handshake_only && !throughput_args.throughput && check == CheckMode::Ping && icmp_count == 0
    {
        bail!("--icmp-count must be at least 1 when --check ping");
    }
    if throughput_args.throughput {
        if throughput_args.throughput_top == 0 {
            bail!("--throughput-top must be at least 1");
        }
        if throughput_args.max_rtt == 0 {
            bail!("--max-rtt must be at least 1");
        }
        if throughput_args.test.test_bytes == 0 {
            bail!("--test-bytes must be greater than 0");
        }
        if throughput_args.test.test_runs == 0 {
            bail!("--test-runs must be at least 1");
        }
        if throughput_args.test.test_url.trim().is_empty() {
            bail!("--test-url must not be empty");
        }
    } else if throughput_args.test.json.is_some() || throughput_args.test.best_out.is_some() {
        bail!("--json and --best-out require --throughput");
    }

    let throughput_enabled = throughput_args.throughput;
    let handshake_only = handshake_only || throughput_enabled;
    let probes = if throughput_enabled {
        probes.max(2)
    } else {
        probes
    };

    let acct = obtain_account(account, new).await?;

    let http_dest = if handshake_only {
        None
    } else {
        resolve_http_dest(check).await?
    };

    let check_desc = if throughput_enabled {
        "handshake only (data-plane throughput stage follows)".to_string()
    } else if handshake_only {
        "handshake only".to_string()
    } else {
        match check {
            CheckMode::Ping => format!("handshake + {icmp_count} ICMP echo(es) to {ping_target}"),
            CheckMode::Trace => "handshake + HTTP GET cdn-cgi/trace (requires warp=on)".to_string(),
            CheckMode::Generate204 => {
                "handshake + HTTP GET generate_204 (requires 204)".to_string()
            }
        }
    };
    if all {
        eprintln!(
            "Exhaustively scanning the full IP\u{00d7}port space, {concurrency} at a time, {probes} probe(s) each, {fake} junk packet(s), {check_desc}..."
        );
    } else {
        eprintln!(
            "Scanning {count} random endpoints, {concurrency} at a time, {probes} probe(s) each, {fake} junk packet(s), {check_desc}..."
        );
    }
    let results = scanner::scan(
        &acct,
        count,
        all,
        concurrency,
        probes,
        fake,
        Duration::from_millis(timeout_ms),
        handshake_only,
        check,
        ping_target,
        icmp_count,
        http_dest,
    )
    .await?;

    if results.is_empty() && !throughput_enabled {
        let what = if handshake_only {
            "completed a handshake"
        } else {
            "passed the check"
        };
        println!("No endpoint {what}. The DPI may be blocking all candidates tried;");
        println!("try a larger --count, a longer --timeout-ms, or run again (ports are sampled).");
        return Ok(());
    }

    if throughput_enabled {
        let opts = throughput_args
            .test
            .options(throughput::DEFAULT_WG_WARPEER_ARGS, Duration::from_secs(25));
        let limit = throughput_args.throughput_top.min(top.max(1));
        let report = throughput::run_wireguard(
            &results,
            &opts,
            limit,
            Duration::from_millis(throughput_args.max_rtt),
        )
        .await?;
        report.print(top);
        report.write_outputs(
            throughput_args.test.json.as_deref(),
            throughput_args.test.best_out.as_deref(),
            top,
        )?;
        return Ok(());
    }

    println!("\nFound {} working endpoint(s):", results.len());
    if handshake_only {
        println!("{:<24}  {:>9}  {:>6}", "ENDPOINT", "RTT(ms)", "LOSS");
        for r in results.iter().take(top) {
            println!(
                "{:<24}  {:>9.1}  {:>5.0}%",
                r.addr.to_string(),
                r.avg_rtt.as_secs_f64() * 1000.0,
                r.loss() * 100.0
            );
        }
    } else if check == CheckMode::Ping {
        println!(
            "{:<24}  {:>9}  {:>9}  {:>6}",
            "ENDPOINT", "HS(ms)", "PING(ms)", "LOSS"
        );
        for r in results.iter().take(top) {
            let ping = r
                .avg_check
                .map(|d| d.as_secs_f64() * 1000.0)
                .unwrap_or(f64::NAN);
            println!(
                "{:<24}  {:>9.1}  {:>9.1}  {:>5.0}%",
                r.addr.to_string(),
                r.avg_rtt.as_secs_f64() * 1000.0,
                ping,
                r.loss() * 100.0
            );
        }
    } else {
        println!(
            "{:<24}  {:>9}  {:>9}  {:>6}  {:<12}",
            "ENDPOINT", "HS(ms)", "HTTP(ms)", "LOSS", "RESULT"
        );
        for r in results.iter().take(top) {
            let http = r
                .avg_check
                .map(|d| d.as_secs_f64() * 1000.0)
                .unwrap_or(f64::NAN);
            println!(
                "{:<24}  {:>9.1}  {:>9.1}  {:>5.0}%  {:<12}",
                r.addr.to_string(),
                r.avg_rtt.as_secs_f64() * 1000.0,
                http,
                r.loss() * 100.0,
                r.detail.as_deref().unwrap_or("-")
            );
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn probe_cmd(
    account: &std::path::Path,
    new: bool,
    endpoint: &str,
    fake: u32,
    timeout_ms: u64,
    handshake_only: bool,
    check: CheckMode,
    ping_target: Ipv4Addr,
    icmp_count: u32,
) -> Result<()> {
    if timeout_ms == 0 {
        bail!("--timeout-ms must be at least 1");
    }
    if !handshake_only && check == CheckMode::Ping && icmp_count == 0 {
        bail!("--icmp-count must be at least 1 when --check ping");
    }

    let acct = obtain_account(account, new).await?;

    let addr = endpoint
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("could not resolve endpoint `{endpoint}`"))?;
    let wait = Duration::from_millis(timeout_ms);

    if handshake_only {
        eprintln!("Probing {addr} with a real WireGuard handshake...");
        let verdict = handshake::probe(
            &acct.private_key,
            &acct.peer_public_key,
            addr,
            OsRng.next_u32(),
            fake,
            wait,
        )
        .await?;
        match verdict.rtt() {
            Some(rtt) => {
                println!(
                    "{addr} => ALIVE, handshake rtt = {:.1} ms",
                    rtt.as_secs_f64() * 1000.0
                )
            }
            None => println!("{addr} => {verdict:?}"),
        }
        return Ok(());
    }

    let src_v4 = acct.client_v4()?;

    match check {
        CheckMode::Ping => {
            eprintln!(
                "Probing {addr}: handshake + {icmp_count} ICMP echo(es) to {ping_target} through the tunnel..."
            );
            let verdict = tunnel::verify(
                &acct.private_key,
                &acct.peer_public_key,
                src_v4,
                ping_target,
                acct.reserved,
                addr,
                OsRng.next_u32(),
                fake,
                wait,
                icmp_count,
            )
            .await?;

            match verdict {
                tunnel::Verdict::Working {
                    handshake_rtt,
                    ping_rtt,
                    ping_sent,
                    ping_received,
                } => println!(
                    "{addr} => WORKING, handshake {:.1} ms, ping {ping_target} avg {:.1} ms ({ping_received}/{ping_sent} received)",
                    handshake_rtt.as_secs_f64() * 1000.0,
                    ping_rtt.as_secs_f64() * 1000.0
                ),
                tunnel::Verdict::HandshakeOnly { handshake_rtt } => println!(
                    "{addr} => HANDSHAKE ONLY (no ping reply), handshake {:.1} ms — endpoint speaks WireGuard but did not route to {ping_target}",
                    handshake_rtt.as_secs_f64() * 1000.0
                ),
                other => println!("{addr} => {other:?}"),
            }
        }
        CheckMode::Trace | CheckMode::Generate204 => {
            let target = if check == CheckMode::Trace {
                http_check::CheckTarget::Trace
            } else {
                http_check::CheckTarget::Generate204
            };
            let dest = resolve_http_dest(check)
                .await?
                .expect("resolved for a non-Ping check");
            eprintln!(
                "Probing {addr}: handshake + HTTP GET http://{}{} through the tunnel...",
                target.host(),
                target.path()
            );
            let verdict = http_check::verify(
                &acct.private_key,
                &acct.peer_public_key,
                src_v4,
                acct.reserved,
                addr,
                dest,
                target,
                OsRng.next_u32(),
                fake,
                wait,
            )
            .await?;

            match verdict {
                http_check::Verdict::Working {
                    handshake_rtt,
                    http_rtt,
                    detail,
                } => println!(
                    "{addr} => WORKING, handshake {:.1} ms, http {:.1} ms, {detail}",
                    handshake_rtt.as_secs_f64() * 1000.0,
                    http_rtt.as_secs_f64() * 1000.0
                ),
                http_check::Verdict::HandshakeOnly { handshake_rtt } => {
                    let expected = match target {
                        http_check::CheckTarget::Trace => "warp=on",
                        http_check::CheckTarget::Generate204 => "204",
                    };
                    println!(
                        "{addr} => HANDSHAKE ONLY (HTTP check failed), handshake {:.1} ms — endpoint speaks WireGuard but http://{}{} did not confirm {expected}",
                        handshake_rtt.as_secs_f64() * 1000.0,
                        target.host(),
                        target.path()
                    )
                }
                other => println!("{addr} => {other:?}"),
            }
        }
    }
    Ok(())
}
