use base64::Engine;
use chrono::{SecondsFormat, Utc};
use sha1::Digest;
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone)]
pub struct PlayRequest {
    pub channel: u32,
    pub subtype: u8,
    pub username: String,
    pub password: String,
    pub realm_label: String,
    pub host_port: u16,
}

#[derive(Debug, Clone)]
pub struct PlayResponse {
    pub status_line: String,
    pub content_type: String,
    pub private_type: Option<String>,
    pub private_length: Option<usize>,
    pub session_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PlayResponseFrame {
    pub response: PlayResponse,
    pub private_body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct MediaCaptureSummary {
    pub output_dir: PathBuf,
    pub private_body_len: usize,
    pub media_chunk_count: usize,
    pub media_bytes: usize,
}

impl PlayRequest {
    pub fn to_http_like(&self) -> String {
        let created = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        let nonce = format!("{:032x}", rand::random::<u128>());
        let ha1 = md5_upper(format!(
            "{}:{}:{}",
            self.username, self.realm_label, self.password
        ));
        let digest = wsse_digest(&nonce, &created, &ha1);

        format!(
            "PLAY /live/realmonitor.xav?channel={}&subtype={}&encrypt=2&method=0 HTTP/1.1\r\n\
Accpet-Sdp: Private\r\n\
Authorization: WSSE profile=\"UsernameToken\"\r\n\
Connect-Type: P2P\r\n\
Connection: keep-alive\r\n\
Cseq: 0\r\n\
Host: 127.0.0.1:{}\r\n\
Speed: 1.000000\r\n\
User-Agent: Http Stream Client/1.0\r\n\
WSSE: UsernameToken Username=\"{}\", PasswordDigest=\"{}\", Nonce=\"{}\", Created=\"{}\"\r\n\r\n",
            self.channel,
            self.subtype,
            self.host_port,
            self.username,
            digest,
            nonce,
            created
        )
    }
}

impl PlayResponse {
    pub fn parse_bytes(data: &[u8]) -> Option<Self> {
        let http_pos = data.windows(b"HTTP/1.1 ".len()).position(|w| w == b"HTTP/1.1 ")?;
        let tail = &data[http_pos..];
        let text = String::from_utf8_lossy(tail);
        let mut lines = text.split("\r\n");
        let status_line = lines.next()?.trim().to_string();
        let mut content_type = None;
        let mut private_type = None;
        let mut private_length = None;
        let mut session_id = None;

        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some(value) = line.strip_prefix("Content-Type:") {
                content_type = Some(value.trim().to_string());
            } else if let Some(value) = line.strip_prefix("Private-Type:") {
                private_type = Some(value.trim().to_string());
            } else if let Some(value) = line.strip_prefix("Private-Length:") {
                private_length = value.trim().parse::<usize>().ok();
            } else if let Some(value) = line.strip_prefix("Session-Id:") {
                session_id = Some(value.trim().to_string());
            }
        }

        Some(Self {
            status_line,
            content_type: content_type?,
            private_type,
            private_length,
            session_id,
        })
    }

    pub fn is_success(&self) -> bool {
        self.status_line == "HTTP/1.1 200 OK" && self.content_type == "video/e-xav"
    }
}

impl PlayResponseFrame {
    pub fn parse_bytes(data: &[u8]) -> Option<Self> {
        let http_pos = data.windows(b"HTTP/1.1 ".len()).position(|w| w == b"HTTP/1.1 ")?;
        let tail = &data[http_pos..];
        let header_end = tail.windows(b"\r\n\r\n".len()).position(|w| w == b"\r\n\r\n")?;
        let body_start = header_end + 4;
        let response = PlayResponse::parse_bytes(tail)?;
        Some(Self {
            response,
            private_body: tail[body_start..].to_vec(),
        })
    }
}

pub fn persist_media_capture(
    base_dir: &Path,
    label: &str,
    response_frame: &PlayResponseFrame,
    media_chunks: &[Vec<u8>],
) -> anyhow::Result<MediaCaptureSummary> {
    let timestamp = Utc::now().format("%Y%m%dT%H%M%SZ");
    let safe_label = label.replace('/', "_");
    let output_dir = base_dir.join(format!("capture_{}_{}", timestamp, safe_label));
    fs::create_dir_all(&output_dir)?;

    let headers_path = output_dir.join("play_response_headers.txt");
    let private_path = output_dir.join("private_sdp.bin");
    let media_path = output_dir.join("media_chunks.bin");
    let chunk_index_path = output_dir.join("media_chunk_index.txt");
    let summary_path = output_dir.join("summary.txt");

    let headers = format!(
        "status={}\ncontent_type={}\nprivate_type={:?}\nprivate_length={:?}\nsession_id={:?}\n",
        response_frame.response.status_line,
        response_frame.response.content_type,
        response_frame.response.private_type,
        response_frame.response.private_length,
        response_frame.response.session_id
    );
    fs::write(&headers_path, headers)?;
    fs::write(&private_path, &response_frame.private_body)?;

    let mut media_blob = Vec::new();
    let mut index = String::new();
    for (i, chunk) in media_chunks.iter().enumerate() {
        use std::fmt::Write as _;
        let _ = writeln!(&mut index, "{} {}", i, chunk.len());
        media_blob.extend_from_slice(chunk);
    }
    fs::write(&media_path, &media_blob)?;
    fs::write(&chunk_index_path, index)?;

    let summary = MediaCaptureSummary {
        output_dir: output_dir.clone(),
        private_body_len: response_frame.private_body.len(),
        media_chunk_count: media_chunks.len(),
        media_bytes: media_blob.len(),
    };
    let summary_text = format!(
        "private_body_len={}\nmedia_chunk_count={}\nmedia_bytes={}\n",
        summary.private_body_len, summary.media_chunk_count, summary.media_bytes
    );
    fs::write(&summary_path, summary_text)?;

    Ok(summary)
}

fn wsse_digest(nonce: &str, created: &str, ha1: &str) -> String {
    let mut sha = sha1::Sha1::new();
    sha.update(nonce.as_bytes());
    sha.update(created.as_bytes());
    sha.update(ha1.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(sha.finalize())
}

fn md5_upper(input: impl AsRef<[u8]>) -> String {
    format!("{:x}", md5::compute(input)).to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::{persist_media_capture, PlayRequest, PlayResponse, PlayResponseFrame};
    use std::fs;

    #[test]
    fn play_request_contains_expected_headers() {
        let req = PlayRequest {
            channel: 1,
            subtype: 1,
            username: "admin".to_string(),
            password: "SS_2024_BS".to_string(),
            realm_label: "Login to 9599eea9d61d3245fb3ad2dce79fa2da".to_string(),
            host_port: 59233,
        }
        .to_http_like();

        assert!(req.starts_with(
            "PLAY /live/realmonitor.xav?channel=1&subtype=1&encrypt=2&method=0 HTTP/1.1\r\n"
        ));
        assert!(req.contains("Authorization: WSSE profile=\"UsernameToken\"\r\n"));
        assert!(req.contains("WSSE: UsernameToken Username=\"admin\""));
        assert!(req.contains("Host: 127.0.0.1:59233\r\n"));
        assert!(req.contains("Speed: 1.000000\r\n"));
        assert!(req.ends_with("\r\n\r\n"));
    }

    #[test]
    fn parses_play_response_with_sdp_prefix() {
        let data = b"HTTP/1.1 200 OK\r\nCache-Control: no-cache\r\nConnection: close\r\nContent-Type: video/e-xav\r\nCseq: 0\r\nKeepLive-Time: 60\r\nPrivate-Length: 740\r\nPrivate-Type: application/sdp\r\nRange: npt=0.000000-\r\nSession-Id: 70245320\r\nUser-Agent: Http Stream Server/1.0\r\n\r\nv=0\r\n";
        let res = PlayResponse::parse_bytes(data).unwrap();
        assert_eq!(res.status_line, "HTTP/1.1 200 OK");
        assert_eq!(res.content_type, "video/e-xav");
        assert_eq!(res.private_type.as_deref(), Some("application/sdp"));
        assert_eq!(res.private_length, Some(740));
        assert_eq!(res.session_id.as_deref(), Some("70245320"));
        assert!(res.is_success());
    }

    #[test]
    fn parses_play_response_frame_and_body() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Type: video/e-xav\r\nPrivate-Length: 5\r\nPrivate-Type: application/sdp\r\nSession-Id: 1\r\n\r\nabcde";
        let frame = PlayResponseFrame::parse_bytes(data).unwrap();
        assert_eq!(frame.response.status_line, "HTTP/1.1 200 OK");
        assert_eq!(frame.private_body, b"abcde");
    }

    #[test]
    fn persists_media_capture_artifacts() {
        let tmp = std::env::temp_dir().join(format!("dmss_poc_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        let frame = PlayResponseFrame {
            response: PlayResponse {
                status_line: "HTTP/1.1 200 OK".to_string(),
                content_type: "video/e-xav".to_string(),
                private_type: Some("application/sdp".to_string()),
                private_length: Some(5),
                session_id: Some("1".to_string()),
            },
            private_body: b"abcde".to_vec(),
        };
        let summary =
            persist_media_capture(&tmp, "main/pub", &frame, &[b"one".to_vec(), b"two".to_vec()])
                .unwrap();
        assert_eq!(summary.private_body_len, 5);
        assert_eq!(summary.media_chunk_count, 2);
        assert_eq!(summary.media_bytes, 6);
        assert!(summary.output_dir.join("play_response_headers.txt").exists());
        assert!(summary.output_dir.join("private_sdp.bin").exists());
        assert!(summary.output_dir.join("media_chunks.bin").exists());
        let _ = fs::remove_dir_all(&tmp);
    }
}
