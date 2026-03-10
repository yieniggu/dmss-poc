use aes::Aes256;
use anyhow::{anyhow, Context, Result};
use base64::Engine;
use hmac::{Hmac, Mac};
use ofb::cipher::{KeyIvInit, StreamCipher};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

use std::net::Ipv4Addr;

const RAND_SALT: &str = "5daf91fc5cfc1be8e081cfb08f792726";
const OFB_IV: &[u8; 16] = b"2z52*lk9o6HRyJrf";

type AesOfb = ofb::Ofb<Aes256>;

#[derive(Debug, Clone)]
pub struct P2pChannelRequest {
    pub serial: String,
    pub username: String,
    pub password: String,
    pub identify: [u8; 8],
    pub local_addr: String,
    pub client_id: String,
}

#[derive(Debug, Clone)]
pub struct ServerNatInfo {
    pub identify: String,
    pub ip_encrypt: bool,
    pub local_addr: String,
    pub nat_value_t: Option<u32>,
    pub policy: Option<String>,
    pub pub_addr: String,
    pub relay: Option<String>,
    pub version: Option<String>,
    pub nonce: Option<u32>,
}

impl P2pChannelRequest {
    pub fn body(&self) -> Result<String> {
        let key = derive_device_auth_key(&self.username, &self.password);
        let nonce = rand::random::<u32>();
        let auth = build_device_auth(&self.username, &key, nonce, &self.local_addr)?;
        let identify = self
            .identify
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");

        Ok(format!(
            "<body>{auth}<Identify>{identify}</Identify><IpEncrpt>true</IpEncrpt><NatValueT>268435455</NatValueT><version>6.7.15</version><sVersion>1.1.0</sVersion><LocalAddr>{}</LocalAddr><Pid>0</Pid><ClientId>{}</ClientId></body>",
            self.local_addr,
            self.client_id
        ))
    }
}

pub fn dmss_style_local_addr(primary_ip: Ipv4Addr, secondary_ip: Ipv4Addr, port: u16) -> String {
    format!(
        "{},{}:{}",
        invert_ipv4(primary_ip),
        invert_ipv4(secondary_ip),
        port
    )
}

pub fn relay_channel_body(
    username: &str,
    password: &str,
    nonce: Option<u32>,
    agent_addr: &str,
) -> Result<String> {
    let auth = if let Some(nonce) = nonce {
        let key = derive_device_auth_key(username, password);
        build_device_auth(username, &key, nonce, "")?
    } else {
        String::new()
    };

    Ok(format!(
        "<body>{auth}<agentAddr>{agent_addr}</agentAddr></body>"
    ))
}

pub fn parse_server_nat_info(body: &std::collections::HashMap<String, String>) -> Result<ServerNatInfo> {
    let identify = body
        .get("body/Identify")
        .cloned()
        .ok_or_else(|| anyhow!("Server Nat Info missing Identify"))?;
    let local_addr = body
        .get("body/LocalAddr")
        .cloned()
        .ok_or_else(|| anyhow!("Server Nat Info missing LocalAddr"))?;
    let pub_addr = body
        .get("body/PubAddr")
        .cloned()
        .ok_or_else(|| anyhow!("Server Nat Info missing PubAddr"))?;

    Ok(ServerNatInfo {
        identify,
        ip_encrypt: body
            .get("body/IpEncrpt")
            .map(|value| value == "true")
            .unwrap_or(false),
        local_addr,
        nat_value_t: body.get("body/NatValueT").and_then(|value| value.parse().ok()),
        policy: body.get("body/Policy").cloned(),
        pub_addr,
        relay: body.get("body/Relay").cloned(),
        version: body.get("body/version").cloned(),
        nonce: body.get("body/Nonce").and_then(|value| value.parse().ok()),
    })
}

pub fn decrypt_local_addr(username: &str, password: &str, nonce: u32, data: &str) -> Result<String> {
    let key = derive_device_auth_key(username, password);
    let mut derived = [0u8; 32];
    pbkdf2_hmac::<Sha256>(&key, nonce.to_string().as_bytes(), 20_000, &mut derived);
    let mut cipher = AesOfb::new_from_slices(&derived, OFB_IV)
        .map_err(|e| anyhow!("Failed to init OFB cipher: {e}"))?;
    let mut bytes = base64::engine::general_purpose::STANDARD
        .decode(data)
        .context("Failed to decode encrypted LocalAddr")?;
    cipher.apply_keystream(&mut bytes);
    String::from_utf8(bytes).context("Decrypted LocalAddr is not UTF-8")
}

fn derive_device_auth_key(username: &str, password: &str) -> Vec<u8> {
    let source = format!("{username}:Login to {RAND_SALT}:{password}");
    format!("{:X}", md5::compute(source.as_bytes())).into_bytes()
}

fn build_device_auth(username: &str, key: &[u8], nonce: u32, payload: &str) -> Result<String> {
    let create_date = chrono::Utc::now().timestamp();
    let message = format!("{nonce}{create_date}{payload}");
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).map_err(|e| anyhow!("Failed to build HMAC key: {e}"))?;
    mac.update(message.as_bytes());
    let auth = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());

    Ok(format!(
        "<CreateDate>{create_date}</CreateDate><DevAuth>{auth}</DevAuth><Nonce>{nonce}</Nonce><RandSalt>{RAND_SALT}</RandSalt><UserName>{username}</UserName>"
    ))
}

fn invert_ipv4(ip: Ipv4Addr) -> String {
    let octets = ip.octets();
    format!(
        "{}.{}.{}.{}",
        !octets[0], !octets[1], !octets[2], !octets[3]
    )
}

#[allow(dead_code)]
fn encrypt_local_addr(key: &[u8], nonce: u32, data: &str) -> Result<String> {
    let mut derived = [0u8; 32];
    pbkdf2_hmac::<Sha256>(key, nonce.to_string().as_bytes(), 20_000, &mut derived);
    let mut cipher =
        AesOfb::new_from_slices(&derived, OFB_IV).map_err(|e| anyhow!("Failed to init OFB cipher: {e}"))?;
    let mut bytes = data.as_bytes().to_vec();
    cipher.apply_keystream(&mut bytes);
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}
