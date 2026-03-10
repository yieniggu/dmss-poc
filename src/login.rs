#[derive(Debug, Clone, Copy)]
pub enum AuthHashStrategy {
    PrefixPlusHa1,
    PrefixPlusMd5Ha1Random,
}

impl AuthHashStrategy {
    pub fn name(self) -> &'static str {
        match self {
            Self::PrefixPlusHa1 => "prefix_plus_ha1",
            Self::PrefixPlusMd5Ha1Random => "prefix_plus_md5_ha1_random",
        }
    }
}

#[derive(Debug, Clone)]
pub struct LoginChallenge {
    pub realm_label: String,
    pub random: String,
}

#[derive(Debug, Clone)]
pub struct LoginResponse {
    pub strategy: AuthHashStrategy,
    pub hash64: String,
    pub token_line: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct LoginAccepted {
    pub function: String,
    pub media_encrypt: String,
}

impl LoginChallenge {
    pub fn parse(text: &str) -> Option<Self> {
        let mut realm_label = None;
        let mut random = None;

        for line in text.lines() {
            if let Some(value) = line.strip_prefix("Realm:") {
                realm_label = Some(value.trim().to_string());
            } else if let Some(value) = line.strip_prefix("Random:") {
                random = Some(value.trim().to_string());
            }
        }

        Some(Self {
            realm_label: realm_label?,
            random: random?,
        })
    }

    pub fn parse_bytes(data: &[u8]) -> Option<Self> {
        // PTCP login payloads carry a binary prefix followed by ASCII lines.
        // Extract the ASCII tail starting from the first "Realm:" marker.
        let realm_pos = data.windows(b"Realm:".len()).position(|w| w == b"Realm:")?;
        let tail = &data[realm_pos..];
        let text = String::from_utf8_lossy(tail);
        Self::parse(text.trim_matches(char::from(0)))
    }
}

impl LoginResponse {
    pub fn build(
        username: &str,
        password: &str,
        challenge: &LoginChallenge,
        strategy: AuthHashStrategy,
    ) -> Self {
        let ha1 = md5_upper(format!(
            "{username}:{}:{password}",
            challenge.realm_label
        ));
        let first32 = md5_upper(format!("{username}:{}:{ha1}", challenge.random));
        let second32 = match strategy {
            AuthHashStrategy::PrefixPlusHa1 => ha1,
            AuthHashStrategy::PrefixPlusMd5Ha1Random => {
                md5_upper(format!("{ha1}:{}", challenge.random))
            }
        };
        let hash64 = format!("{first32}{second32}");
        let token_line = format!("{username}&&{hash64}");
        let payload = build_login_payload(&token_line);

        Self {
            strategy,
            hash64,
            token_line,
            payload,
        }
    }
}

impl LoginAccepted {
    pub fn parse_bytes(data: &[u8]) -> Option<Self> {
        let function_pos = data
            .windows(b"Function:".len())
            .position(|w| w == b"Function:")?;
        let tail = &data[function_pos..];
        let text = String::from_utf8_lossy(tail);

        let mut function = None;
        let mut media_encrypt = None;
        for line in text.lines() {
            if let Some(value) = line.strip_prefix("Function:") {
                function = Some(value.trim().to_string());
            } else if let Some(value) = line.strip_prefix("MediaEncrypt:") {
                media_encrypt = Some(value.trim().to_string());
            }
        }

        Some(Self {
            function: function?,
            media_encrypt: media_encrypt?,
        })
    }
}

fn build_login_payload(token_line: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(32 + token_line.len());
    payload.extend_from_slice(&[0xa0, 0x05, 0x00, 0x60]);
    payload.extend_from_slice(&(token_line.len() as u32).to_le_bytes());
    payload.extend_from_slice(&[0; 16]);
    payload.extend_from_slice(&[0x04, 0x02, 0x09, 0x08, 0x00, 0x00, 0xa1, 0xaa]);
    payload.extend_from_slice(token_line.as_bytes());
    payload
}

fn md5_upper(input: impl AsRef<[u8]>) -> String {
    format!("{:x}", md5::compute(input)).to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::{AuthHashStrategy, LoginAccepted, LoginChallenge, LoginResponse};

    #[test]
    fn parses_realm_and_random() {
        let challenge = LoginChallenge::parse("Realm:Login to abc\r\nRandom:12345\r\n").unwrap();
        assert_eq!(challenge.realm_label, "Login to abc");
        assert_eq!(challenge.random, "12345");
    }

    #[test]
    fn parses_bytes_with_nuls() {
        let bytes = b"Realm:Login to realm\r\nRandom:42\r\n\0\0";
        let challenge = LoginChallenge::parse_bytes(bytes).unwrap();
        assert_eq!(challenge.realm_label, "Login to realm");
        assert_eq!(challenge.random, "42");
    }

    #[test]
    fn parses_bytes_with_binary_prefix() {
        let bytes = [
            &[0xb0, 0x01, 0x00, 0x78, 0x46, 0x00, 0x00, 0x00][..],
            b"Realm:Login to 9599eea9d61d3245fb3ad2dce79fa2da\r\n",
            b"Random:1891286319\r\n\r\n",
        ]
        .concat();
        let challenge = LoginChallenge::parse_bytes(&bytes).unwrap();
        assert_eq!(
            challenge.realm_label,
            "Login to 9599eea9d61d3245fb3ad2dce79fa2da"
        );
        assert_eq!(challenge.random, "1891286319");
    }

    #[test]
    fn builds_login_response_with_known_prefix32() {
        let challenge = LoginChallenge {
            realm_label: "Login to 9599eea9d61d3245fb3ad2dce79fa2da".to_string(),
            random: "5785976470".to_string(),
        };
        let response = LoginResponse::build(
            "admin",
            "SS_2024_BS",
            &challenge,
            AuthHashStrategy::PrefixPlusHa1,
        );
        assert_eq!(
            &response.hash64[..32],
            "B81E78C263BA81E7D33FE2DF11BCE57B"
        );
        assert!(response.token_line.starts_with("admin&&"));
        assert_eq!(response.payload[0..4], [0xa0, 0x05, 0x00, 0x60]);
    }

    #[test]
    fn parses_login_accepted_with_binary_prefix() {
        let bytes = [
            &[0xb0, 0x01, 0x00, 0x78, 0x25, 0x00, 0x00, 0x00][..],
            b"Function:0x00000184\r\nMediaEncrypt:2\r\n",
        ]
        .concat();
        let accepted = LoginAccepted::parse_bytes(&bytes).unwrap();
        assert_eq!(accepted.function, "0x00000184");
        assert_eq!(accepted.media_encrypt, "2");
    }
}
