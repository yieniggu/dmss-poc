use async_trait::async_trait;
use base64::Engine;
use sha1::Digest;
use std::{collections::HashMap, net::UdpSocket as StdUdpSocket};
use tokio::net::UdpSocket;
use xml::reader::{EventReader, XmlEvent};

pub const MAIN_SERVER: &str = "www.easy4ipcloud.com:8800";
pub const CLOUD_USERNAME: &str = "cba1b29e32cb17aa46b8ff9e73c7f40b";
pub const CLOUD_USERKEY: &str = "996103384cdf19179e19243e959bbf8b";

#[derive(Debug, Clone)]
pub struct DhResponse {
    pub version: String,
    pub code: u16,
    pub status: String,
    pub headers: HashMap<String, String>,
    pub body: Option<HashMap<String, String>>,
}

pub fn ephemeral_client_id(port: u16) -> String {
    format!("{:032x}:{port}", rand::random::<u128>())
}

fn parse_xml(text: &str) -> HashMap<String, String> {
    let mut path: Vec<String> = Vec::new();
    let mut out = HashMap::new();
    let parser = EventReader::from_str(text);

    for event in parser {
        match event {
            Ok(XmlEvent::StartElement { name, .. }) => path.push(name.local_name),
            Ok(XmlEvent::EndElement { .. }) => {
                let _ = path.pop();
            }
            Ok(XmlEvent::Characters(value)) => {
                if !value.trim().is_empty() && !path.is_empty() {
                    out.insert(path.join("/"), value);
                }
            }
            _ => {}
        }
    }

    out
}

fn wsse_header(cseq: i32) -> String {
    let nonce = rand::random::<u32>();
    let created = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let mut sha = sha1::Sha1::new();
    sha.update(format!(
        "{nonce}{created}DHP2P:{CLOUD_USERNAME}:{CLOUD_USERKEY}"
    ));
    let digest = base64::engine::general_purpose::STANDARD.encode(sha.finalize());

    format!(
        "CSeq: {cseq}\r\nAuthorization: WSSE profile=\"UsernameToken\"\r\nX-WSSE: UsernameToken Username=\"{CLOUD_USERNAME}\", PasswordDigest=\"{digest}\", Nonce=\"{nonce}\", Created=\"{created}\""
    )
}

fn parse_response(raw: &str) -> DhResponse {
    let mut sections = raw.splitn(2, "\r\n\r\n");
    let head = sections.next().unwrap_or_default();
    let body_text = sections.next().unwrap_or_default();

    let mut lines = head.lines();
    let status_line = lines.next().unwrap_or("HTTP/1.1 500 Invalid");
    let mut status_parts = status_line.splitn(3, ' ');

    let version = status_parts.next().unwrap_or_default().to_string();
    let code = status_parts
        .next()
        .unwrap_or("500")
        .parse::<u16>()
        .unwrap_or(500);
    let status = status_parts.next().unwrap_or_default().to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            headers.insert(key.trim().to_string(), value.trim().to_string());
        }
    }

    let body = if body_text.trim().is_empty() {
        None
    } else {
        Some(parse_xml(body_text))
    };

    DhResponse {
        version,
        code,
        status,
        headers,
        body,
    }
}

#[async_trait]
pub trait DhTransport {
    async fn dh_request(&self, path: &str, body: Option<&str>, cseq: &mut i32) -> anyhow::Result<()>;
    async fn dh_request_with_headers(
        &self,
        path: &str,
        body: Option<&str>,
        extra_headers: &[(&str, &str)],
        cseq: &mut i32,
    ) -> anyhow::Result<()>;
    async fn dh_read_raw(&self) -> anyhow::Result<DhResponse>;
}

#[async_trait]
impl DhTransport for UdpSocket {
    async fn dh_request(&self, path: &str, body: Option<&str>, cseq: &mut i32) -> anyhow::Result<()> {
        self.dh_request_with_headers(path, body, &[], cseq).await
    }

    async fn dh_request_with_headers(
        &self,
        path: &str,
        body: Option<&str>,
        extra_headers: &[(&str, &str)],
        cseq: &mut i32,
    ) -> anyhow::Result<()> {
        *cseq += 1;
        let method = if body.is_some() { "DHPOST" } else { "DHGET" };
        let extra_headers = if extra_headers.is_empty() {
            String::new()
        } else {
            extra_headers
                .iter()
                .map(|(key, value)| format!("{key}: {value}\r\n"))
                .collect::<String>()
        };
        let payload = match body {
            Some(body) => format!(
                "{method} {path} HTTP/1.1\r\nX-Version: 6.7.15\r\nX-Sversion: 1.1.0\r\n{extra_headers}X-ToUType: Client/Dmss_Android\r\n{}\r\nContent-Type: \r\nContent-Length: {}\r\n\r\n{}",
                wsse_header(*cseq),
                body.len(),
                body
            ),
            None => format!(
                "{method} {path} HTTP/1.1\r\nX-Version: 6.7.15\r\nX-Sversion: 1.1.0\r\n{extra_headers}X-ToUType: Client/Dmss_Android\r\n{}\r\n\r\n",
                wsse_header(*cseq)
            ),
        };

        self.send(payload.as_bytes()).await?;
        Ok(())
    }

    async fn dh_read_raw(&self) -> anyhow::Result<DhResponse> {
        let mut buf = [0u8; 8192];
        let n = self.recv(&mut buf).await?;
        let text = String::from_utf8_lossy(&buf[..n]).to_string();
        Ok(parse_response(&text))
    }
}

pub async fn bind_udp() -> anyhow::Result<UdpSocket> {
    let std_socket = StdUdpSocket::bind("0.0.0.0:0")?;
    std_socket.set_nonblocking(true)?;
    Ok(UdpSocket::from_std(std_socket)?)
}
