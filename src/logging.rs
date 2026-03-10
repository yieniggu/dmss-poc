use crate::stun::RoleAttr;
use std::net::SocketAddr;

pub fn format_role(role: Option<&RoleAttr>) -> String {
    match role {
        Some(RoleAttr::Controlling(value)) => format!("controlling:{value:016x}"),
        Some(RoleAttr::Controlled(value)) => format!("controlled:{value:016x}"),
        None => "-".to_string(),
    }
}

pub fn format_socket(socket: Option<&SocketAddr>) -> String {
    socket
        .map(ToString::to_string)
        .unwrap_or_else(|| "-".to_string())
}

pub fn hex_slice(bytes: &[u8], limit: usize) -> String {
    bytes[0..bytes.len().min(limit)]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::hex_slice;

    #[test]
    fn hex_slice_limits_output() {
        let bytes = [0x01, 0x02, 0xaa, 0xff];
        assert_eq!(hex_slice(&bytes, 2), "01 02");
        assert_eq!(hex_slice(&bytes, 10), "01 02 aa ff");
    }
}
