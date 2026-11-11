//! Data-plane throughput testing.
//!
//! The handshake scan only proves that an endpoint speaks WireGuard. This stage
//! spawns the real `warpeer` client for the best handshake survivors, sees
//! whether the tunnel becomes usable, and downloads a fixed byte budget through
//! its local SOCKS5 proxy. Throughput is measured as bytes / wall time, so it
//! includes the TCP/TLS setup just like `curl` does.

use std::collections::BTreeMap;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use serde::Serialize;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};

use crate::scanner::EndpointResult;

/// A reliable ~40 MB tarball; the Range request caps each sample at
/// `--test-bytes` (20 MB by default).
pub const DEFAULT_TEST_URL: &str =
    "https://registry.npmjs.org/@next/swc-linux-x64-gnu/-/swc-linux-x64-gnu-14.2.5.tgz";
pub const DEFAULT_TEST_BYTES: u64 = 20_000_000;
pub const DEFAULT_TEST_RUNS: u32 = 2;

/// Production settings used on the test box for the WireGuard data path.
pub const DEFAULT_WG_WARPEER_ARGS: &[&str] = &[
    "--jc",
    "8",
    "--jmin",
    "50",
    "--jmax",
    "200",
    "--jdelay",
    "15",
    "--tcp-buf",
    "2048",
];

/// Production settings for the MASQUE data path.
pub const DEFAULT_MASQUE_WARPEER_ARGS: &[&str] = &["--tcp-buf", "2048", "--mtu", "1400"];

#[derive(Debug, Clone, Args)]
pub struct TestArgs {
    /// URL downloaded through the tunnel for throughput samples.
    #[arg(long, default_value = DEFAULT_TEST_URL)]
    pub test_url: String,
    /// Byte budget per sample (an HTTP Range request is used when possible).
    #[arg(long, default_value_t = DEFAULT_TEST_BYTES)]
    pub test_bytes: u64,
    /// Samples per endpoint; the median is reported.
    #[arg(long, default_value_t = DEFAULT_TEST_RUNS)]
    pub test_runs: u32,
    /// Timeout for one sample, in milliseconds.
    #[arg(long, default_value_t = 60_000)]
    pub test_timeout_ms: u64,
    /// warpeer binary used for the data-plane test.
    #[arg(long, default_value = "warpeer")]
    pub warpeer_bin: PathBuf,
    /// Extra warpeer arguments. Defaults to the production obfs/TCP settings.
    #[arg(long, default_value = "")]
    pub warpeer_args: String,
    /// Reuse this warpeer cache directory instead of a temporary one.
    #[arg(long)]
    pub warpeer_cache_dir: Option<PathBuf>,
    /// Write machine-readable results to this JSON file.
    #[arg(long)]
    pub json: Option<PathBuf>,
    /// Write one endpoint per line to this file.
    #[arg(long)]
    pub best_out: Option<PathBuf>,
}

impl TestArgs {
    pub fn options(&self, default_args: &[&str], startup_timeout: Duration) -> TestOptions {
        let warpeer_args = if self.warpeer_args.trim().is_empty() {
            default_args.iter().map(|s| s.to_string()).collect()
        } else {
            self.warpeer_args
                .split_whitespace()
                .map(|s| s.to_string())
                .collect()
        };
        TestOptions {
            warpeer_bin: self.warpeer_bin.clone(),
            warpeer_args,
            test_url: self.test_url.clone(),
            test_bytes: self.test_bytes,
            test_runs: self.test_runs,
            test_timeout: Duration::from_millis(self.test_timeout_ms.max(1)),
            startup_timeout,
            cache_dir: self.warpeer_cache_dir.clone(),
        }
    }
}

#[derive(Debug, Clone, Args)]
pub struct ThroughputArgs {
    /// Also measure data-plane throughput for the best handshake survivors.
    #[arg(long, default_value_t = false)]
    pub throughput: bool,
    /// How many handshake survivors to throughput-test (capped by --top).
    #[arg(long, default_value_t = 8)]
    pub throughput_top: usize,
    /// Reject handshake survivors slower than this RTT (milliseconds).
    #[arg(long, default_value_t = 500)]
    pub max_rtt: u64,
    #[command(flatten)]
    pub test: TestArgs,
}

#[derive(Debug, Clone)]
pub struct TestOptions {
    pub warpeer_bin: PathBuf,
    pub warpeer_args: Vec<String>,
    pub test_url: String,
    pub test_bytes: u64,
    pub test_runs: u32,
    pub test_timeout: Duration,
    pub startup_timeout: Duration,
    pub cache_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TestParameters {
    pub url: String,
    pub bytes: u64,
    pub runs: u32,
    pub warpeer_bin: String,
    pub warpeer_args: String,
    pub direct_mbps: Option<f64>,
    pub direct_mb_s: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThroughputResult {
    pub endpoint: String,
    pub transport: String,
    pub handshake_ms: Option<f64>,
    pub loss: Option<f64>,
    pub throughput_mbps: f64,
    pub throughput_mb_s: f64,
    pub samples_mbps: Vec<f64>,
    pub stable: bool,
    pub score: f64,
    pub warpeer_cmd: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThroughputReport {
    pub transport: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    pub test: TestParameters,
    pub results: Vec<ThroughputResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups: Option<BTreeMap<String, Vec<ThroughputResult>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    WireGuard,
    Masque,
}

#[derive(Debug, Clone)]
pub struct Measurement {
    pub samples_mbps: Vec<f64>,
    pub transport: String,
}

/// A temporary directory that removes itself on drop. Used for warpeer
/// identities and per-candidate MASQUE config copies (both hold secrets).
pub struct TempDir {
    path: PathBuf,
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

impl TempDir {
    pub fn new(prefix: &str) -> Result<Self> {
        let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("{prefix}-{}-{n}", std::process::id()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .with_context(|| format!("creating {}", path.display()))?;
        }
        #[cfg(not(unix))]
        {
            std::fs::create_dir_all(&path)
                .with_context(|| format!("creating {}", path.display()))?;
        }
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Run the throughput stage for WireGuard handshake survivors.
pub async fn run_wireguard(
    results: &[EndpointResult],
    opts: &TestOptions,
    limit: usize,
    max_rtt: Duration,
) -> Result<ThroughputReport> {
    if opts.test_bytes == 0 {
        bail!("--test-bytes must be greater than 0");
    }
    if limit == 0 {
        bail!("--throughput-top must be greater than 0");
    }

    let candidates: Vec<&EndpointResult> = results
        .iter()
        .filter(|r| r.successes >= 1)
        .filter(|r| r.loss() <= 0.20)
        .filter(|r| r.avg_rtt <= max_rtt)
        .take(limit)
        .collect();

    let direct = measure_direct(opts).await.ok();

    let temp_cache = if opts.cache_dir.is_none() {
        Some(TempDir::new("warpscan-wg-cache")?)
    } else {
        None
    };
    let cache_path = match &opts.cache_dir {
        Some(path) => path.clone(),
        None => temp_cache
            .as_ref()
            .expect("temporary cache was created")
            .path()
            .to_path_buf(),
    };
    std::fs::create_dir_all(&cache_path)
        .with_context(|| format!("creating warpeer cache {}", cache_path.display()))?;

    let mut out = Vec::with_capacity(candidates.len());
    for r in candidates {
        let endpoint = r.addr;
        let mut args = opts.warpeer_args.clone();
        args.push("-e".to_string());
        args.push(endpoint.to_string());
        args.push("--cache-dir".to_string());
        args.push(cache_path.to_string_lossy().to_string());
        let warpeer_cmd = wireguard_command(opts, endpoint);

        match measure_candidate(opts, &args, Expect::WireGuard).await {
            Ok(m) => {
                let mut samples = m.samples_mbps;
                let (median, jitter, stable) = summarize(&mut samples);
                let loss = r.loss();
                let handshake_ms = r.avg_rtt.as_secs_f64() * 1000.0;
                let score = median * (1.0 - loss) - 0.25 * jitter;
                out.push(ThroughputResult {
                    endpoint: endpoint.to_string(),
                    transport: m.transport,
                    handshake_ms: Some(handshake_ms),
                    loss: Some(loss),
                    throughput_mbps: median,
                    throughput_mb_s: median / 8.0,
                    samples_mbps: samples,
                    stable,
                    score,
                    warpeer_cmd,
                    error: None,
                });
            }
            Err(e) => out.push(ThroughputResult {
                endpoint: endpoint.to_string(),
                transport: "wireguard".to_string(),
                handshake_ms: Some(r.avg_rtt.as_secs_f64() * 1000.0),
                loss: Some(r.loss()),
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

    sort_results(&mut out);
    Ok(ThroughputReport {
        transport: "wireguard".to_string(),
        mode: None,
        test: test_parameters(opts, direct),
        results: out,
        groups: None,
    })
}

pub(crate) fn test_parameters(opts: &TestOptions, direct: Option<f64>) -> TestParameters {
    TestParameters {
        url: opts.test_url.clone(),
        bytes: opts.test_bytes,
        runs: opts.test_runs,
        warpeer_bin: opts.warpeer_bin.display().to_string(),
        warpeer_args: opts.warpeer_args.join(" "),
        direct_mbps: direct,
        direct_mb_s: direct.map(|m| m / 8.0),
    }
}

pub fn sort_results(results: &mut [ThroughputResult]) {
    results.sort_by(|a, b| {
        a.error.is_some().cmp(&b.error.is_some()).then_with(|| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    });
}

pub fn group_by_transport(results: &[ThroughputResult]) -> BTreeMap<String, Vec<ThroughputResult>> {
    let mut groups = BTreeMap::new();
    for r in results.iter().filter(|r| r.error.is_none()) {
        groups
            .entry(r.transport.clone())
            .or_insert_with(Vec::new)
            .push(r.clone());
    }
    for list in groups.values_mut() {
        sort_results(list);
    }
    groups
}

impl ThroughputReport {
    pub fn print(&self, top: usize) {
        match (self.test.direct_mbps, self.test.direct_mb_s) {
            (Some(mbps), Some(mb_s)) => {
                println!("Direct line reference: {mb_s:.1} MB/s ({mbps:.1} Mbps)");
            }
            _ => println!("Direct line reference: unavailable"),
        }
        if let Some(mode) = &self.mode {
            println!("MASQUE mode: {mode}");
        }

        let valid: Vec<&ThroughputResult> =
            self.results.iter().filter(|r| r.error.is_none()).collect();
        if valid.is_empty() {
            println!("No endpoint passed the throughput test.");
            let failed = self.results.iter().filter(|r| r.error.is_some()).count();
            if failed > 0 {
                println!("{failed} candidate(s) failed; see the JSON output for details.");
            }
            return;
        }

        if let Some(groups) = &self.groups {
            for (transport, results) in groups {
                println!("\n{transport}:");
                print_table(results, top);
            }
        } else {
            println!("\nThroughput (WireGuard):");
            print_table(&valid.iter().map(|r| (*r).clone()).collect::<Vec<_>>(), top);
        }

        if let Some(best) = valid.first() {
            println!("\nWithin-tunnel command: {}", best.warpeer_cmd);
        }
        let failed = self.results.iter().filter(|r| r.error.is_some()).count();
        if failed > 0 {
            println!("{failed} candidate(s) failed; see the JSON output for details.");
        }
    }

    pub fn write_outputs(
        &self,
        json: Option<&Path>,
        best_out: Option<&Path>,
        top: usize,
    ) -> Result<()> {
        if let Some(path) = json {
            let data = serde_json::to_string_pretty(self)?;
            std::fs::write(path, data)
                .with_context(|| format!("writing JSON results to {}", path.display()))?;
        }
        if let Some(path) = best_out {
            let mut body = String::new();
            for r in self.results.iter().filter(|r| r.error.is_none()).take(top) {
                body.push_str(&r.endpoint);
                body.push('\n');
            }
            std::fs::write(path, body)
                .with_context(|| format!("writing best endpoints to {}", path.display()))?;
        }
        Ok(())
    }
}

fn print_table(results: &[ThroughputResult], top: usize) {
    println!(
        "{:<24}  {:>8}  {:>6}  {:>8}  {:>8}  {:>7}  {:>8}",
        "ENDPOINT", "HS(ms)", "LOSS", "MB/s", "Mbps", "STABLE", "SCORE"
    );
    for r in results.iter().filter(|r| r.error.is_none()).take(top) {
        let hs = r
            .handshake_ms
            .map(|v| format!("{v:.1}"))
            .unwrap_or_else(|| "-".to_string());
        let loss = r
            .loss
            .map(|v| format!("{:.0}%", v * 100.0))
            .unwrap_or_else(|| "-".to_string());
        println!(
            "{:<24}  {:>8}  {:>6}  {:>8.1}  {:>8.1}  {:>7}  {:>8.1}",
            r.endpoint,
            hs,
            loss,
            r.throughput_mb_s,
            r.throughput_mbps,
            if r.stable { "yes" } else { "no" },
            r.score
        );
    }
}

/// Spawn warpeer, wait for its mixed proxy, then run the throughput samples.
pub async fn measure_candidate(
    opts: &TestOptions,
    args: &[String],
    expect: Expect,
) -> Result<Measurement> {
    if opts.test_bytes == 0 {
        bail!("test byte budget must be greater than 0");
    }
    let port = free_port()?;
    let mut child = Command::new(&opts.warpeer_bin)
        .args(args)
        .arg("-b")
        .arg(format!("127.0.0.1:{port}"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("spawning warpeer ({})", opts.warpeer_bin.display()))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("warpeer stdout was not captured"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("warpeer stderr was not captured"))?;
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    spawn_lines(stdout, tx.clone());
    spawn_lines(stderr, tx);

    let outcome = async {
        let transport = wait_ready(&mut child, &mut rx, port, opts.startup_timeout, expect).await?;
        let client = build_client(Some(port), opts.test_timeout)?;

        let mut samples = Vec::new();
        let mut last_err = None;
        for _ in 0..opts.test_runs.max(1) {
            match download_once(&client, &opts.test_url, opts.test_bytes).await {
                Ok(mbps) => samples.push(mbps),
                Err(e) => last_err = Some(e),
            }
        }
        if samples.is_empty() {
            return Err(last_err.unwrap_or_else(|| anyhow!("no throughput samples")));
        }
        Ok(Measurement {
            samples_mbps: samples,
            transport,
        })
    }
    .await;

    let _ = child.kill().await;
    let _ = child.wait().await;
    outcome
}

fn spawn_lines<R>(reader: R, tx: mpsc::UnboundedSender<String>)
where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut lines = BufReader::new(reader).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
}

async fn wait_ready(
    child: &mut Child,
    rx: &mut mpsc::UnboundedReceiver<String>,
    port: u16,
    wait: Duration,
    expect: Expect,
) -> Result<String> {
    let deadline = Instant::now() + wait;
    let mut transport = match expect {
        Expect::WireGuard => Some("wireguard".to_string()),
        Expect::Masque => None,
    };

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("warpeer did not serve its proxy within {wait:?}");
        }

        tokio::select! {
            line = rx.recv() => {
                match line {
                    Some(line) => {
                        if let Some(t) = parse_transport(&line) {
                            transport = Some(t.to_string());
                        }
                        if line.contains("serving proxy") {
                            if matches!(expect, Expect::Masque) && transport.is_none() {
                                let _ = timeout(
                                    Duration::from_secs(2),
                                    wait_for_transport(rx, &mut transport),
                                ).await;
                            }
                            return Ok(transport.unwrap_or_else(|| "unknown".to_string()));
                        }
                    }
                    None => {
                        if let Ok(Some(status)) = child.try_wait() {
                            bail!("warpeer exited before serving its proxy ({status})");
                        }
                        bail!("warpeer output closed before serving its proxy");
                    }
                }
            }
            _ = sleep(Duration::from_millis(250)) => {
                if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                    return Ok(transport.unwrap_or_else(|| "unknown".to_string()));
                }
                if let Ok(Some(status)) = child.try_wait() {
                    bail!("warpeer exited before serving its proxy ({status})");
                }
            }
        }
    }
}

async fn wait_for_transport(
    rx: &mut mpsc::UnboundedReceiver<String>,
    transport: &mut Option<String>,
) {
    while let Some(line) = rx.recv().await {
        if let Some(t) = parse_transport(&line) {
            *transport = Some(t.to_string());
            return;
        }
        if line.contains("serving proxy") {
            return;
        }
    }
}

fn parse_transport(line: &str) -> Option<&'static str> {
    if line.contains("MASQUE transport: HTTP/3") {
        Some("HTTP/3")
    } else if line.contains("MASQUE transport: HTTP/2") {
        Some("HTTP/2")
    } else {
        None
    }
}

pub(crate) fn free_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("finding a free local port")?;
    Ok(listener.local_addr()?.port())
}

fn build_client(proxy_port: Option<u16>, wait: Duration) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(wait)
        .no_proxy()
        .user_agent("warpscan-throughput/0.1");
    if let Some(port) = proxy_port {
        let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}"))
            .context("building SOCKS5 proxy URL")?;
        builder = builder.proxy(proxy);
    }
    builder.build().context("building throughput HTTP client")
}

pub async fn measure_direct(opts: &TestOptions) -> Result<f64> {
    let client = build_client(None, opts.test_timeout)?;
    download_once(&client, &opts.test_url, opts.test_bytes).await
}

async fn download_once(client: &reqwest::Client, url: &str, bytes: u64) -> Result<f64> {
    let start = Instant::now();
    let mut response = client
        .get(url)
        .header(
            reqwest::header::RANGE,
            format!("bytes=0-{}", bytes.saturating_sub(1)),
        )
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .header(reqwest::header::CONNECTION, "close")
        .send()
        .await
        .context("throughput request failed")?;
    if !response.status().is_success() {
        bail!("throughput target returned HTTP {}", response.status());
    }

    let mut total = 0u64;
    while total < bytes {
        match response
            .chunk()
            .await
            .context("reading throughput response")?
        {
            Some(chunk) => {
                let take = ((bytes - total) as usize).min(chunk.len());
                total += take as u64;
            }
            None => break,
        }
    }
    if total == 0 {
        bail!("throughput target returned no data");
    }
    let elapsed = start.elapsed().as_secs_f64();
    if elapsed <= 0.0 {
        bail!("invalid throughput timing");
    }
    Ok(total as f64 * 8.0 / elapsed / 1_000_000.0)
}

pub(crate) fn summarize(samples: &mut Vec<f64>) -> (f64, f64, bool) {
    // Drop an obviously slow first sample (TCP/TLS warm-up) when there are
    // enough samples left to keep the median meaningful.
    if samples.len() >= 3 {
        let rest_median = median(&samples[1..]);
        if samples[0] < rest_median * 0.5 {
            samples.remove(0);
        }
    }
    let med = median(samples);
    let (min, max) = samples
        .iter()
        .fold((f64::INFINITY, f64::NEG_INFINITY), |(lo, hi), &v| {
            (lo.min(v), hi.max(v))
        });
    let jitter = if samples.is_empty() { 0.0 } else { max - min };
    let stable = samples.len() < 2 || jitter <= med * 0.4;
    (med, jitter, stable)
}

fn median(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mid = sorted.len() / 2;
    if sorted.len().is_multiple_of(2) {
        (sorted[mid - 1] + sorted[mid]) / 2.0
    } else {
        sorted[mid]
    }
}

fn wireguard_command(opts: &TestOptions, endpoint: SocketAddr) -> String {
    let mut parts = vec![
        opts.warpeer_bin.display().to_string(),
        "-e".to_string(),
        endpoint.to_string(),
    ];
    parts.extend(opts.warpeer_args.iter().cloned());
    shell_join(&parts)
}

pub fn shell_join(parts: &[String]) -> String {
    parts
        .iter()
        .map(|p| {
            if p.chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_./:=@".contains(c))
            {
                p.clone()
            } else {
                format!("'{}'", p.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn median_handles_even_and_odd_samples() {
        assert_eq!(median(&[10.0, 2.0, 8.0]), 8.0);
        assert_eq!(median(&[10.0, 2.0]), 6.0);
    }

    #[test]
    fn summarize_flags_unstable_throughput() {
        let mut samples = vec![10.0, 2.0];
        let (median, jitter, stable) = summarize(&mut samples);
        assert_eq!(median, 6.0);
        assert_eq!(jitter, 8.0);
        assert!(!stable);
    }

    #[test]
    fn parses_masque_transport_logs() {
        assert_eq!(
            parse_transport("MASQUE transport: HTTP/2 (TLS/TCP)"),
            Some("HTTP/2")
        );
        assert_eq!(
            parse_transport("MASQUE transport: HTTP/3 (QUIC)"),
            Some("HTTP/3")
        );
        assert_eq!(parse_transport("serving proxy"), None);
    }

    #[test]
    fn shell_join_quotes_spaces() {
        assert_eq!(
            shell_join(&["warpeer".into(), "-e".into(), "a b".into()]),
            "warpeer -e 'a b'"
        );
    }
}
