# warpscan

[![CI](https://github.com/Ho3einWave/warpscan/actions/workflows/ci.yml/badge.svg)](https://github.com/Ho3einWave/warpscan/actions/workflows/ci.yml)

Cloudflare WARP endpoint scanner that verifies candidates with a **real
WireGuard handshake**, checks end-to-end connectivity through the tunnel, and
optionally ranks the survivors by **actual data-plane throughput** using the
`warpeer` client. A separate MASQUE mode ranks HTTP/2 and HTTP/3 endpoints. It
registers its own WARP account directly with Cloudflare, so it does not depend
on `wgcf` or `warp-plus`.

## CI and releases

Pushes and pull requests to `main` run formatting, Clippy, tests, and the
Linux/Windows release builds. Pushing a version tag publishes a GitHub Release
with both binaries:

```sh
git tag v0.2.0
git push origin v0.2.0
```

Release assets:

- `warpscan-x86_64-unknown-linux-gnu.tar.gz`
- `warpscan-x86_64-pc-windows-msvc.zip`

## Build

```sh
cargo build --release          # target/release/warpscan
cargo test                     # unit tests
```

On Windows, `build.ps1` builds both the native Windows binary and a Linux
binary via WSL:

```powershell
.\build.ps1                 # release, both targets
.\build.ps1 -Target linux   # Linux only
.\build.ps1 -Dev            # debug profile
```

## Usage

The first run registers a WARP account and writes it to `warp-account.json`
(override with `--account`). Later runs reuse it; pass `--new` to register a
fresh account.

```sh
# Smoke-test one endpoint with a real handshake.
warpscan probe 162.159.192.1:2408 --handshake-only

# Require the tunnel to actually reach Cloudflare as WARP (default check).
warpscan probe 162.159.192.1:2408 --check trace

# Scan 400 random candidates, best 10 printed.
warpscan scan --count 400 --concurrency 100 --top 10

# Sweep every known IPv4 endpoint and every WARP port.
warpscan scan --all --handshake-only

# Three ICMP echoes through each tunnel (instead of HTTP).
warpscan scan --check ping --ping-target 1.1.1.1
```

Run `warpscan scan --help` for every flag.

### Checks

| `--check` | What it does |
| --- | --- |
| `trace` (default) | `GET http://www.cloudflare.com/cdn-cgi/trace` through the tunnel and require `warp=on` in the body. Strongest signal that traffic really left through WARP. |
| `generate204` | `GET http://www.gstatic.com/generate_204` through the tunnel and require a `204`. Lighter check. |
| `ping` | Sends ICMP echo requests to `--ping-target` through the tunnel and requires a reply. |

`--handshake-only` skips all of the above and only requires a WireGuard
handshake response. It is the fastest option, but an endpoint can pass it
without actually routing traffic.

## Data-plane throughput

Handshake RTT is a poor predictor of real speed. `--throughput` keeps the
handshake sweep as a cheap liveness filter, then spawns the real `warpeer`
client for the best survivors and measures an actual download through the
tunnel.

```sh
warpscan scan --throughput --top 5 \
  --warpeer-bin /opt/warpeer/warpeer \
  --warpeer-cache-dir ~/.cache/warpeer \
  --test-bytes 20000000 --test-runs 2 \
  --json throughput.json --best-out best.txt
```

For each candidate the scanner:

1. Picks a free `127.0.0.1` port.
2. Starts `warpeer -e <endpoint> -b 127.0.0.1:<port>` with the production
   obfuscation/TCP settings (`--jc 8 --jmin 50 --jmax 200 --jdelay 15
   --tcp-buf 2048`).
3. Waits for the log line `serving proxy` (or a TCP connect fallback).
4. Downloads the test URL through the SOCKS5 proxy with an HTTP Range request.
5. Kills the child and removes its temporary cache.

Defaults:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--throughput-top` | `8` | Handshake survivors to test, capped by `--top` |
| `--max-rtt` | `500` | Reject survivors slower than this (ms) |
| `--test-url` | npm SWC tarball | Range-capable test payload |
| `--test-bytes` | `20000000` | Bytes per sample |
| `--test-runs` | `2` | Samples per endpoint; the median is reported |
| `--test-timeout-ms` | `60000` | Timeout per sample |
| `--warpeer-args` | production obfs/TCP args | Override `warpeer` arguments |
| `--warpeer-cache-dir` | temporary | Reuse a warpeer identity instead of registering a temp one |

`--throughput` forces a handshake-only sweep (the data-plane test is the real
quality signal). The direct line speed is measured once per scan for context.
The reported score is:

```
median_throughput_mbps * (1 - loss) - 0.25 * throughput_jitter_mbps
```

An endpoint is marked unstable when its samples differ by more than 40% of the
median. The JSON records both Mbps and MB/s, the raw samples, handshake RTT,
loss, stability, score, and a ready-to-use `warpeer -e ...` command. Endpoint
quality changes over time, so rescan periodically and keep a rolling best set.

## MASQUE

MASQUE is a separate transport with its own endpoint space
(`162.159.198.0/24`, `2606:4700:103::/64`, port 443) and a separate ECDSA device
config. The `masque` subcommand rewrites only the endpoint field in a temporary
copy of a usque-compatible `masque.json`, starts `warpeer --masque`, and
measures the same download.

```sh
# Force HTTP/2 (the reliable path when UDP/443 is filtered).
warpscan masque --h2 --count 8 --top 5 \
  --warpeer-bin /root/warpeer-masque \
  --masque-config /root/.cache/warpeer-masque/masque.json \
  --test-bytes 20000000 --test-runs 2 \
  --json masque.json --best-out masque-best.txt

# Auto: try HTTP/3, fall back to HTTP/2. Transport is read from warpeer's log.
warpscan masque --count 8

# HTTP/3 only; fails honestly instead of falling back.
warpscan masque --h3-only --count 4
```

If `--masque-config` is omitted, the scanner runs `warpeer --masque` once to
register a temporary device and keeps the generated config in
`--warpeer-cache-dir` (or a temp directory removed after the scan). The config
contains private key/token material: it is written with mode `0600`, never
copied into the JSON, and temp copies are deleted after each candidate.

Results are grouped by the transport warpeer actually used (`HTTP/2` or
`HTTP/3`), because the two are not directly comparable. On networks where
UDP/443 is filtered, use `--h2`; otherwise every H3 attempt costs the H3
connect timeout before falling back. `--ipv6` selects the IPv6 candidate range;
`--all` covers all 256 IPv4 candidates (sequential, so it is slow).

Reference numbers on a ~120 Mbps line (they vary with time of day and load):

- Direct 30 MB npm download: 9–14 MB/s.
- WireGuard + 2 MiB TCP buffer: 11–14 MB/s.
- MASQUE over HTTP/2 with MTU 1400: 4.6–6.0 MB/s.
- MASQUE over HTTP/3: faster where UDP/443 is available; unavailable on the
  reference network.

## How it works

- `src/warp.rs` registers an X25519 keypair with Cloudflare and stores the
  client id (`reserved`), addresses, and peer key.
- `src/handshake.rs` sends a real Noise IKpsk2 handshake initiation and
  validates the response with `boringtun`.
- `src/tunnel.rs` verifies connectivity by building ICMP echo requests inside
  the tunnel, with no TUN device.
- `src/http_check.rs` bridges `boringtun` to a minimal userspace TCP stack
  (`smoltcp`) for a real HTTP GET through the tunnel.
- `src/scanner.rs` samples or exhausts the known IPv4 WARP ranges and ports,
  runs probes concurrently, and ranks the results.
- `src/throughput.rs` spawns `warpeer` per survivor, waits for its proxy, and
  measures downloads over SOCKS5.
- `src/masque_scan.rs` rewrites MASQUE configs per candidate and ranks the
  actual H2/H3 transport.

`--fake N` sends `N` random UDP packets before each handshake to make DPI
fingerprinting harder; set it to `0` for a plain probe. The default is `8`.
In DPI-filtered networks a plain handshake (`--fake 0`) can time out while
`--fake 8` succeeds; try `--fake 16` or `--fake 32` if handshakes still fail.

Packet loss can be high on filtered paths. Use `--probes 2` or `--probes 3`
and a larger `--timeout-ms` when scanning, and check the reported loss column.

## Account file

`warp-account.json` contains the WireGuard private key. It is created with mode
`0600` on Unix, and older files are tightened on load. Do not commit it (it is
in `.gitignore`).

## Limitations

- WireGuard scanning covers IPv4 endpoints only; MASQUE can scan IPv6 with
  `--ipv6`.
- MASQUE requires a `warpeer` build with MASQUE support and a device config.
- HTTP/3 depends on UDP/443 being available; otherwise force `--h2`.
- The throughput stage downloads `--test-bytes` per sample and spawns one
  `warpeer` per candidate, so it is intentionally slower than handshake-only
  scanning.
- The HTTP checks use plain HTTP (no TLS) to keep the userspace stack small.
- Check targets are resolved before probing; DNS must work outside the tunnel.
