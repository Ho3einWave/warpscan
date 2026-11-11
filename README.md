# warpscan

[![CI](https://github.com/Ho3einWave/warpscan/actions/workflows/ci.yml/badge.svg)](https://github.com/Ho3einWave/warpscan/actions/workflows/ci.yml)

Cloudflare WARP endpoint scanner that verifies candidates with a **real
WireGuard handshake** and, optionally, an end-to-end connectivity check through
the tunnel. It registers its own WARP account directly with Cloudflare, so it
does not depend on `wgcf` or `warp-plus`.

## CI and releases

Pushes and pull requests to `main` run formatting, Clippy, tests, and the
Linux/Windows release builds. Pushing a version tag publishes a GitHub Release
with both binaries:

```sh
git tag v0.1.0
git push origin v0.1.0
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

- IPv4 endpoints only.
- The HTTP checks use plain HTTP (no TLS) to keep the userspace stack small.
- Check targets are resolved before probing; DNS must work outside the tunnel.
