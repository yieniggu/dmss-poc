use anyhow::{anyhow, Result};
use std::net::SocketAddr;

const STUN_COOKIE: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS_RESPONSE: u16 = 0x0101;
const ATTR_ICE_CONTROLLING: u16 = 0x802A;
const ATTR_ICE_CONTROLLED: u16 = 0x8029;
const ATTR_SOURCE_ADDRESS: u16 = 0x0004;

#[derive(Debug, Clone)]
pub enum RoleAttr {
    Controlling(u64),
    Controlled(u64),
}

#[derive(Debug, Clone)]
pub struct StunMessage {
    pub message_type: u16,
    pub transaction_id: [u8; 12],
    pub role: Option<RoleAttr>,
    pub source_address: Option<SocketAddr>,
    pub inverted: bool,
}

impl StunMessage {
    pub fn binding_request(tie_breaker: u64, source_address: SocketAddr) -> Result<(Self, Vec<u8>)> {
        let transaction_id = rand::random::<[u8; 12]>();
        let mut attrs = Vec::new();

        attrs.extend_from_slice(&ATTR_ICE_CONTROLLING.to_be_bytes());
        attrs.extend_from_slice(&(8u16).to_be_bytes());
        attrs.extend_from_slice(&tie_breaker.to_be_bytes());

        attrs.extend_from_slice(&ATTR_SOURCE_ADDRESS.to_be_bytes());
        attrs.extend_from_slice(&(8u16).to_be_bytes());
        attrs.push(0x00);
        attrs.push(match source_address {
            SocketAddr::V4(_) => 0x01,
            SocketAddr::V6(_) => return Err(anyhow!("IPv6 STUN addresses are not supported")),
        });
        attrs.extend_from_slice(&source_address.port().to_be_bytes());
        match source_address {
            SocketAddr::V4(addr) => attrs.extend_from_slice(&addr.ip().octets()),
            SocketAddr::V6(_) => return Err(anyhow!("IPv6 STUN addresses are not supported")),
        }

        let mut bytes = Vec::with_capacity(20 + attrs.len());
        bytes.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
        bytes.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&STUN_COOKIE.to_be_bytes());
        bytes.extend_from_slice(&transaction_id);
        bytes.extend_from_slice(&attrs);

        Ok((
            Self {
                message_type: BINDING_REQUEST,
                transaction_id,
                role: Some(RoleAttr::Controlling(tie_breaker)),
                source_address: Some(source_address),
                inverted: false,
            },
            bytes,
        ))
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        Self::parse_internal(bytes, false)
    }

    pub fn parse_normal_or_inverted(bytes: &[u8]) -> Result<Self> {
        match Self::parse_internal(bytes, false) {
            Ok(message) => Ok(message),
            Err(_) => {
                let inverted = invert_bytes(bytes);
                Self::parse_internal(&inverted, true)
            }
        }
    }

    fn parse_internal(bytes: &[u8], inverted: bool) -> Result<Self> {
        if bytes.len() < 20 {
            return Err(anyhow!("STUN packet too short"));
        }

        let message_type = u16::from_be_bytes([bytes[0], bytes[1]]);
        let message_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        let cookie = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if cookie != STUN_COOKIE {
            return Err(anyhow!("Invalid STUN cookie"));
        }
        if bytes.len() < 20 + message_len {
            return Err(anyhow!("Truncated STUN message"));
        }

        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(&bytes[8..20]);

        let mut role = None;
        let mut source_address = None;
        let mut offset = 20usize;
        let end = 20 + message_len;

        while offset + 4 <= end {
            let attr_type = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
            let attr_len = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
            offset += 4;
            if offset + attr_len > end {
                return Err(anyhow!("Invalid STUN attribute length"));
            }
            let value = &bytes[offset..offset + attr_len];

            match attr_type {
                ATTR_ICE_CONTROLLING if attr_len == 8 => {
                    role = Some(RoleAttr::Controlling(u64::from_be_bytes(value.try_into().unwrap())));
                }
                ATTR_ICE_CONTROLLED if attr_len == 8 => {
                    role = Some(RoleAttr::Controlled(u64::from_be_bytes(value.try_into().unwrap())));
                }
                ATTR_SOURCE_ADDRESS if attr_len == 8 => {
                    let family = value[1];
                    if family == 0x01 {
                        let port = u16::from_be_bytes([value[2], value[3]]);
                        let ip = std::net::Ipv4Addr::new(value[4], value[5], value[6], value[7]);
                        source_address = Some(SocketAddr::from((ip, port)));
                    }
                }
                _ => {}
            }

            offset += attr_len;
            let padding = (4 - (attr_len % 4)) % 4;
            offset += padding;
        }

        Ok(Self {
            message_type,
            transaction_id,
            role,
            source_address,
            inverted,
        })
    }

    pub fn is_binding_success(&self) -> bool {
        self.message_type == BINDING_SUCCESS_RESPONSE
    }
}

fn invert_bytes(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().map(|b| !b).collect()
}
