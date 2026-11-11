//! MASQUE data-plane testing.
//!
//! MASQUE uses its own endpoint space and identity: `162.159.198.0/24` (and
//! `2606:4700:103::/64`) on TCP/UDP 443, with an ECDSA MASQUE device config.
//! For each candidate we make a temp copy of an existing `masque.json`, rewrite
//! only the endpoint field, spawn warpeer, and measure the same SOCKS5 download
//! used by the WireGuard throughput stage.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use rand_core::{OsRng, RngCore};
use serde_json::Value;
use tokio::process::Command;
use tokio::time::sleep;

use crate::throughput::{
    self, Expect, TempDir, TestArgs, TestOptions, ThroughputReport, ThroughputResult,
};

const MASQUE_V4_PREFIX: [u8; 3] = [162, 159, 198];
const MASQUE_V6_PREFIX: [u16; 4] = [0x2606, 0x4700, 0x0103, 0];

#[derive(Debug, Clone, Args)]
pub struct MasqueArgs {
    /// Number of random MASQUE candidate IPs to test.
    #[arg(long, default_value_t = 16)]
    pub count: usize,
    /// Test all 256 IPv4 candidates in 162.159.198.0/24.
    #[arg(long, default_value_t = false)]
    pub all: bool,
    /// Force HTTP/2 (recommended when UDP/443 is filtered).
    #[arg(long, default_value_t = false)]
    pub h2: bool,
    /// Test HTTP/3 only; disable the HTTP/2 fallback.
    #[arg(long, default_value_t = false)]
    pub h3_only: bool,
    /// Test IPv6 candidates from 2606:4700:103::/64 instead of IPv4.
    #[arg(long, default_value_t = false)]
    pub ipv6: bool,
    /// Existing usque-compatible MASQUE config. If omitted, warpeer registers
    /// a temporary device and creates one.
    #[arg(long)]
    pub masque_config: Option<PathBuf>,
    /// How many best results to print.
    #[arg(long, default_value_t = 8)]
    pub top: usize,
    /// Timeout for one warpeer MASQUE startup, in milliseconds.
    #[arg(long, default_value_t = 45_000)]
    pub startup_timeout_ms: u64,
    #[command(flatten)]
    pub test: TestArgs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    H2,
    Auto,
    H3Only,
}

impl Mode {
    fn label(self) -> &'static str {
        match self {
            Mode::H2 => "h2",
            Mode::Auto => "auto",
            Mode::H3Only => "h3-only",
        }
    }
}

pub async fn run(args: MasqueArgs) -> Result<()> {
    if args.h2 && args.h3_only {
        bail!("--h2 and --h3-only cannot be combined");
    }
    if args.count == 0 && !args.all {
        bail!("--count must be at least 1");
    }
    if args.all && args.ipv6 {
        bail!("--all is only supported for IPv4 MASQUE candidates");
    }
    if args.top == 0 {
        bail!("--top must be at least 1");
    }
    if args.test.test_bytes == 0 {
        bail!("--test-bytes must be greater than 0");
    }
    if args.test.test_runs == 0 {
        bail!("--test-runs must be at least 1");
    }
    if args.test.test_url.trim().is_empty() {
        bail!("--test-url must not be empty");
    }

    let mode = if args.h3_only {
        Mode::H3Only
    } else if args.h2 {
        Mode::H2
    } else {
        Mode::Auto
    };

    let opts = args.test.options(
        throughput::DEFAULT_MASQUE_WARPEER_ARGS,
        Duration::from_millis(args.startup_timeout_ms.max(1)),
    );
    let base = ensure_config(&args, &opts).await?;
    let candidates = candidates(&args);
    let direct = throughput::measure_direct(&opts).await.ok();

    let mut results = Vec::with_capacity(candidates.len());
    for ip in candidates {
        let endpoint = format!("{ip}:443");
        let warpeer_cmd = masque_command(&opts, mode);
        let measurement = async {
            let config_dir = TempDir::new("warpscan-masque-cfg")?;
            let config_path = config_dir.path().join("masque.json");
            write_endpoint_config(&base.path, &config_path, ip, mode)?;

            let mut warpeer_args = opts.warpeer_args.clone();
            warpeer_args.push("--masque".to_string());
            if mode == Mode::H2 {
                warpeer_args.push("--masque-h2".to_string());
            }
            warpeer_args.push(if ip.is_ipv6() {
                "-6".to_string()
            } else {
                "-4".to_string()
            });
            warpeer_args.push("--masque-config".to_string());
            warpeer_args.push(config_path.to_string_lossy().to_string());

            throughput::measure_candidate(&opts, &warpeer_args, Expect::Masque).await
        }
        .await;

        match measurement {
            Ok(m) => {
                let mut samples = m.samples_mbps;
                let (median, jitter, stable) = throughput::summarize(&mut samples);
                results.push(ThroughputResult {
                    endpoint,
                    transport: m.transport,
                    handshake_ms: None,
                    loss: None,
                    throughput_mbps: median,
                    throughput_mb_s: median / 8.0,
                    samples_mbps: samples,
                    stable,
                    score: median - 0.25 * jitter,
                    warpeer_cmd,
                    error: None,
                });
            }
            Err(e) => results.push(ThroughputResult {
                endpoint,
                transport: if mode == Mode::H2 {
                    "HTTP/2".to_string()
                } else {
                    "unknown".to_string()
                },
                handshake_ms: None,
                loss: None,
                throughput_mbps: 0.0,
                throughput_mb_s: 0.0,
                samples_mbps: Vec::new(),
                stable: false,
                score: 0.0,
                warpeer_cmd,
                error: Some(e.to_string()),
            }),
        }
    }

    throughput::sort_results(&mut results);
    let groups = throughput::group_by_transport(&results);
    let report = ThroughputReport {
        transport: "masque".to_string(),
        mode: Some(mode.label().to_string()),
        test: throughput::test_parameters(&opts, direct),
        results,
        groups: Some(groups),
    };
    report.print(args.top);
    report.write_outputs(
        args.test.json.as_deref(),
        args.test.best_out.as_deref(),
        args.top,
    )?;
    Ok(())
}

struct BaseConfig {
    path: PathBuf,
    _guard: Option<TempDir>,
}

async fn ensure_config(args: &MasqueArgs, opts: &TestOptions) -> Result<BaseConfig> {
    if let Some(path) = &args.masque_config {
        if !path.exists() {
            bail!("MASQUE config {} does not exist", path.display());
        }
        return Ok(BaseConfig {
            path: path.clone(),
            _guard: None,
        });
    }

    if let Some(cache) = &args.test.warpeer_cache_dir {
        let path = cache.join("masque.json");
        if path.exists() {
            return Ok(BaseConfig { path, _guard: None });
        }
        std::fs::create_dir_all(cache)
            .with_context(|| format!("creating warpeer cache {}", cache.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(cache, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("restricting permissions on {}", cache.display()))?;
        }
        generate_config(cache, &path, opts).await?;
        return Ok(BaseConfig { path, _guard: None });
    }

    let guard = TempDir::new("warpscan-masque")?;
    let path = guard.path().join("masque.json");
    generate_config(guard.path(), &path, opts).await?;
    Ok(BaseConfig {
        path,
        _guard: Some(guard),
    })
}

async fn generate_config(cache: &Path, config: &Path, opts: &TestOptions) -> Result<()> {
    let port = throughput::free_port()?;
    let mut child = Command::new(&opts.warpeer_bin)
        .arg("--masque")
        .arg("--cache-dir")
        .arg(cache)
        .arg("-b")
        .arg(format!("127.0.0.1:{port}"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| {
            format!(
                "spawning {} for MASQUE registration",
                opts.warpeer_bin.display()
            )
        })?;

    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if config.exists() {
            if let Ok(bytes) = std::fs::read(config) {
                if serde_json::from_slice::<Value>(&bytes).is_ok() {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    return Ok(());
                }
            }
        }
        if let Some(status) = child.try_wait()? {
            bail!("warpeer exited during MASQUE registration ({status})");
        }
        if Instant::now() >= deadline {
            let _ = child.kill().await;
            let _ = child.wait().await;
            bail!("timed out waiting for warpeer to create masque.json");
        }
        sleep(Duration::from_millis(500)).await;
    }
}

fn candidates(args: &MasqueArgs) -> Vec<IpAddr> {
    if args.ipv6 {
        let n = args.count.max(1);
        return (0..n)
            .map(|_| {
                let a = OsRng.next_u32() as u16;
                let b = OsRng.next_u32() as u16;
                let c = OsRng.next_u32() as u16;
                let d = OsRng.next_u32() as u16;
                IpAddr::V6(Ipv6Addr::new(
                    MASQUE_V6_PREFIX[0],
                    MASQUE_V6_PREFIX[1],
                    MASQUE_V6_PREFIX[2],
                    MASQUE_V6_PREFIX[3],
                    a,
                    b,
                    c,
                    d,
                ))
            })
            .collect();
    }

    let mut out = Vec::new();
    if args.all {
        for host in 0..=255u8 {
            out.push(IpAddr::V4(Ipv4Addr::new(
                MASQUE_V4_PREFIX[0],
                MASQUE_V4_PREFIX[1],
                MASQUE_V4_PREFIX[2],
                host,
            )));
        }
        return out;
    }

    let n = args.count.clamp(1, 256);
    // The fixed HTTP/2 fallback address is worth testing first.
    out.push(IpAddr::V4(Ipv4Addr::new(
        MASQUE_V4_PREFIX[0],
        MASQUE_V4_PREFIX[1],
        MASQUE_V4_PREFIX[2],
        2,
    )));
    let mut hosts: Vec<u8> = (0..=255).filter(|h| *h != 2).collect();
    for i in (1..hosts.len()).rev() {
        let j = (OsRng.next_u32() as usize) % (i + 1);
        hosts.swap(i, j);
    }
    for host in hosts.into_iter().take(n.saturating_sub(1)) {
        out.push(IpAddr::V4(Ipv4Addr::new(
            MASQUE_V4_PREFIX[0],
            MASQUE_V4_PREFIX[1],
            MASQUE_V4_PREFIX[2],
            host,
        )));
    }
    out
}

fn write_endpoint_config(base: &Path, dest: &Path, ip: IpAddr, mode: Mode) -> Result<()> {
    let raw =
        std::fs::read(base).with_context(|| format!("reading MASQUE config {}", base.display()))?;
    let mut value: Value = serde_json::from_slice(&raw).context("parsing MASQUE config as JSON")?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| anyhow!("MASQUE config is not a JSON object"))?;

    let endpoint = ip.to_string();
    let h3_field = if ip.is_ipv6() {
        "endpoint_v6"
    } else {
        "endpoint_v4"
    };
    let h2_field = if ip.is_ipv6() {
        "endpoint_h2_v6"
    } else {
        "endpoint_h2_v4"
    };

    match mode {
        Mode::H2 => {
            object.insert(h2_field.to_string(), Value::String(endpoint));
        }
        Mode::Auto => {
            object.insert(h3_field.to_string(), Value::String(endpoint.clone()));
            object.insert(h2_field.to_string(), Value::String(endpoint));
        }
        Mode::H3Only => {
            object.insert(h3_field.to_string(), Value::String(endpoint));
            object.insert(
                h2_field.to_string(),
                Value::String(if ip.is_ipv6() { "::1" } else { "127.0.0.1" }.to_string()),
            );
        }
    }

    let data = serde_json::to_vec_pretty(&value)?;
    std::fs::write(dest, data)
        .with_context(|| format!("writing MASQUE config {}", dest.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dest, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("restricting permissions on {}", dest.display()))?;
    }
    Ok(())
}

fn masque_command(opts: &TestOptions, mode: Mode) -> String {
    let mut parts = vec![
        opts.warpeer_bin.display().to_string(),
        "--masque".to_string(),
    ];
    if mode == Mode::H2 {
        parts.push("--masque-h2".to_string());
    }
    parts.push("--masque-config".to_string());
    parts.push("<masque-config>".to_string());
    parts.extend(opts.warpeer_args.iter().cloned());
    throughput::shell_join(&parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_candidates_start_with_h2_fallback_and_are_unique() {
        let args = MasqueArgs {
            count: 5,
            all: false,
            h2: false,
            h3_only: false,
            ipv6: false,
            masque_config: None,
            top: 8,
            startup_timeout_ms: 1,
            test: TestArgs {
                test_url: String::new(),
                test_bytes: 1,
                test_runs: 1,
                test_timeout_ms: 1,
                warpeer_bin: PathBuf::new(),
                warpeer_args: String::new(),
                warpeer_cache_dir: None,
                json: None,
                best_out: None,
            },
        };
        let list = candidates(&args);
        assert_eq!(list.len(), 5);
        assert_eq!(list[0], "162.159.198.2".parse::<IpAddr>().unwrap());
        let unique: std::collections::HashSet<_> = list.iter().collect();
        assert_eq!(unique.len(), list.len());
    }
}
