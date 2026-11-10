//! Self-contained Cloudflare WARP account registration (the wgcf / warp-plus
//! approach). We generate our own X25519 keypair and register it directly with
//! `api.cloudflareclient.com`, so there is no third-party dependency.
//!
//! The registered private key becomes our WireGuard *initiator* static key; the
//! returned peer public key + addresses + client_id (-> `reserved`) feed both
//! the handshake probe and the emitted sing-box config.

use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use boringtun::x25519::{PublicKey, StaticSecret};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

const API_BASE: &str = "https://api.cloudflareclient.com/v0a2158";
const CF_CLIENT_VERSION: &str = "a-6.10-2158";
const USER_AGENT: &str = "okhttp/3.12.1";
/// Registration must not hang forever on a captive portal or a blackholed
/// route; 30 s is plenty for the API call itself.
const REGISTER_TIMEOUT: Duration = Duration::from_secs(30);

/// Everything we need from a registered WARP account.
#[derive(Clone)]
pub struct WarpAccount {
    pub private_key: StaticSecret,
    pub public_key: PublicKey,
    pub peer_public_key: PublicKey,
    pub address_v4: String,
    pub address_v6: String,
    /// Decoded client_id, used as the `reserved` field by sing-box/xray.
    pub reserved: [u8; 3],
    pub endpoint_host: String,
}

#[derive(Deserialize)]
struct RegResponse {
    config: RegConfig,
}
#[derive(Deserialize)]
struct RegConfig {
    peers: Vec<RegPeer>,
    interface: RegInterface,
    client_id: String,
}
#[derive(Deserialize)]
struct RegPeer {
    public_key: String,
    endpoint: RegEndpoint,
}
#[derive(Deserialize)]
struct RegEndpoint {
    host: String,
}
#[derive(Deserialize)]
struct RegInterface {
    addresses: RegAddresses,
}
#[derive(Deserialize)]
struct RegAddresses {
    v4: String,
    v6: String,
}

/// Generate a fresh keypair and register it with Cloudflare.
pub async fn register() -> Result<WarpAccount> {
    let b64 = base64::engine::general_purpose::STANDARD;

    let private = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&private);
    let pub_b64 = b64.encode(public.as_bytes());

    let body = serde_json::json!({
        "install_id": "",
        "tos": "2021-01-01T00:00:00.000+00:00",
        "key": pub_b64,
        "fcm_token": "",
        "type": "Android",
        "locale": "en_US",
    });

    let client = reqwest::Client::new();
    let resp: RegResponse = client
        .post(format!("{API_BASE}/reg"))
        .header("User-Agent", USER_AGENT)
        .header("CF-Client-Version", CF_CLIENT_VERSION)
        .header("Content-Type", "application/json")
        .json(&body)
        .timeout(REGISTER_TIMEOUT)
        .send()
        .await
        .context("registration request failed")?
        .error_for_status()
        .context("registration returned an error status")?
        .json()
        .await
        .context("could not parse registration response")?;

    let peer = resp
        .config
        .peers
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("registration response had no peers"))?;

    let peer_bytes = b64.decode(peer.public_key.trim())?;
    let peer_arr: [u8; 32] = peer_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("peer public key was not 32 bytes"))?;
    let peer_public = PublicKey::from(peer_arr);

    let cid = b64.decode(resp.config.client_id.trim())?;
    if cid.len() < 3 {
        return Err(anyhow!("client_id decoded to fewer than 3 bytes"));
    }
    let reserved = [cid[0], cid[1], cid[2]];

    Ok(WarpAccount {
        private_key: private,
        public_key: public,
        peer_public_key: peer_public,
        address_v4: resp.config.interface.addresses.v4,
        address_v6: resp.config.interface.addresses.v6,
        reserved,
        endpoint_host: peer.endpoint.host,
    })
}

/// On-disk form of a WARP account: keys stored as base64 since the x25519 types
/// aren't directly serializable.
#[derive(Serialize, Deserialize)]
struct StoredAccount {
    private_key: String,
    public_key: String,
    peer_public_key: String,
    address_v4: String,
    address_v6: String,
    reserved: [u8; 3],
    endpoint_host: String,
}

fn decode_key(s: &str) -> Result<[u8; 32]> {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("stored key was not 32 bytes"))
}

impl WarpAccount {
    /// Our WireGuard-assigned IPv4, parsed out of `address_v4` (e.g.
    /// "172.16.0.2/32"). This is the source address for tunneled packets.
    pub fn client_v4(&self) -> Result<Ipv4Addr> {
        let ip = self.address_v4.split('/').next().unwrap_or("");
        ip.parse().map_err(|_| {
            anyhow!(
                "account address_v4 `{}` is not a valid IPv4",
                self.address_v4
            )
        })
    }

    fn to_stored(&self) -> StoredAccount {
        let b64 = base64::engine::general_purpose::STANDARD;
        StoredAccount {
            private_key: b64.encode(self.private_key.to_bytes()),
            public_key: b64.encode(self.public_key.as_bytes()),
            peer_public_key: b64.encode(self.peer_public_key.as_bytes()),
            address_v4: self.address_v4.clone(),
            address_v6: self.address_v6.clone(),
            reserved: self.reserved,
            endpoint_host: self.endpoint_host.clone(),
        }
    }

    fn from_stored(s: StoredAccount) -> Result<Self> {
        Ok(WarpAccount {
            private_key: StaticSecret::from(decode_key(&s.private_key)?),
            public_key: PublicKey::from(decode_key(&s.public_key)?),
            peer_public_key: PublicKey::from(decode_key(&s.peer_public_key)?),
            address_v4: s.address_v4,
            address_v6: s.address_v6,
            reserved: s.reserved,
            endpoint_host: s.endpoint_host,
        })
    }
}

fn save(acct: &WarpAccount, path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(&acct.to_stored())?;
    std::fs::write(path, json).with_context(|| format!("writing account to {}", path.display()))?;
    restrict_permissions(path)
}

/// The saved account contains the WireGuard private key, so keep it readable
/// only by its owner. On Windows the default ACLs already do the equivalent.
#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restricting permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn load(path: &Path) -> Result<WarpAccount> {
    let data = std::fs::read_to_string(path)
        .with_context(|| format!("reading account from {}", path.display()))?;
    // Tighten accounts created by older versions, which used the default
    // (usually 0644) mode.
    if let Err(e) = restrict_permissions(path) {
        eprintln!("warning: {e:#}");
    }
    let stored: StoredAccount =
        serde_json::from_str(&data).context("parsing saved account file")?;
    WarpAccount::from_stored(stored)
}

/// Reuse the saved account at `path` if it exists (and `force_new` is false),
/// otherwise register a fresh one and save it. The returned bool is true when a
/// new account was registered.
pub async fn load_or_register(path: &Path, force_new: bool) -> Result<(WarpAccount, bool)> {
    if !force_new && path.exists() {
        return Ok((load(path)?, false));
    }
    let acct = register().await?;
    save(&acct, path)?;
    Ok((acct, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account_with_address(address_v4: &str) -> WarpAccount {
        let private = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&private);
        WarpAccount {
            private_key: private,
            public_key: public,
            peer_public_key: public,
            address_v4: address_v4.to_string(),
            address_v6: "2606:4700:100::1/128".to_string(),
            reserved: [1, 2, 3],
            endpoint_host: "engage.cloudflareclient.com".to_string(),
        }
    }

    #[test]
    fn client_v4_parses_cidr_address() {
        let acct = account_with_address("172.16.0.2/32");
        assert_eq!(acct.client_v4().unwrap(), Ipv4Addr::new(172, 16, 0, 2));
    }

    #[test]
    fn client_v4_rejects_garbage() {
        let acct = account_with_address("not-an-ip");
        assert!(acct.client_v4().is_err());
    }

    #[test]
    fn stored_account_round_trips() {
        let acct = account_with_address("172.16.0.2/32");
        let restored = WarpAccount::from_stored(acct.to_stored()).unwrap();
        assert_eq!(restored.client_v4().unwrap(), acct.client_v4().unwrap());
        assert_eq!(restored.reserved, acct.reserved);
        assert_eq!(restored.address_v6, acct.address_v6);
    }
}
