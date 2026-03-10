use crate::{
    bootstrap::BootstrapContext,
    logging::{format_role, format_socket, hex_slice},
    stun::StunMessage,
};
use anyhow::{anyhow, Context, Result};
use std::net::{SocketAddr, SocketAddrV4};
use tokio::time::{timeout, Duration};

pub async fn perform_stun(context: BootstrapContext) -> Result<BootstrapContext> {
    let device_addr: SocketAddr = context
        .main_nat
        .local_addr
        .parse()
        .with_context(|| format!("Invalid device LocalAddr {}", context.main_nat.local_addr))?;
    let public_addr: SocketAddr = context
        .main_nat
        .pub_addr
        .parse()
        .with_context(|| format!("Invalid device PubAddr {}", context.main_nat.pub_addr))?;
    let second_device_addr: SocketAddr = context
        .aux_nat
        .local_addr
        .parse()
        .with_context(|| format!("Invalid aux LocalAddr {}", context.aux_nat.local_addr))?;
    let second_public_addr: SocketAddr = context
        .aux_nat
        .pub_addr
        .parse()
        .with_context(|| format!("Invalid aux PubAddr {}", context.aux_nat.pub_addr))?;

    let raw_phase =
        perform_raw_punch(&context.main_socket, public_addr, device_addr, context.main_identify)
            .await?;
    println!(
        "[raw] summary first_response={} followups={} binding_success={}",
        raw_phase.first_response_len, raw_phase.followup_count, raw_phase.binding_success_count
    );
    let raw_phase_aux = perform_raw_punch(
        &context.aux_socket,
        second_public_addr,
        second_device_addr,
        context.aux_identify,
    )
    .await?;
    println!(
        "[raw] summary_aux first_response={} followups={} binding_success={}",
        raw_phase_aux.first_response_len,
        raw_phase_aux.followup_count,
        raw_phase_aux.binding_success_count
    );

    println!("[stun] socket1 targets: lan={device_addr} pub={public_addr}");
    println!("[stun] socket2 targets: lan={} pub={}", second_device_addr, second_public_addr);

    let primary_tie_breaker = u64::from_be_bytes(context.main_identify);
    let secondary_tie_breaker = u64::from_be_bytes(context.aux_identify);

    let (_, socket1_lan) = StunMessage::binding_request(primary_tie_breaker, device_addr)?;
    let (_, socket1_pub) = StunMessage::binding_request(primary_tie_breaker, public_addr)?;
    let (_, socket2_lan) = StunMessage::binding_request(secondary_tie_breaker, second_device_addr)?;
    let (_, socket2_pub) =
        StunMessage::binding_request(secondary_tie_breaker, second_public_addr)?;

    println!(
        "[stun] request socket1/lan tie_breaker={:016x}",
        primary_tie_breaker
    );
    context.main_socket.connect(device_addr).await?;
    context.main_socket.send(&socket1_lan).await?;
    let mut socket1_messages =
        receive_stun_window(&context.main_socket, "socket1/lan", Duration::from_millis(350)).await?;
    println!(
        "[stun] request socket1/pub tie_breaker={:016x}",
        primary_tie_breaker
    );
    context.main_socket.connect(public_addr).await?;
    context.main_socket.send(&socket1_pub).await?;
    socket1_messages.extend(
        receive_stun_window(&context.main_socket, "socket1/pub", Duration::from_millis(700)).await?,
    );

    println!(
        "[stun] request socket2/lan tie_breaker={:016x}",
        secondary_tie_breaker
    );
    context.aux_socket.connect(second_device_addr).await?;
    context.aux_socket.send(&socket2_lan).await?;
    let mut socket2_messages =
        receive_stun_window(&context.aux_socket, "socket2/lan", Duration::from_millis(350)).await?;
    println!(
        "[stun] request socket2/pub tie_breaker={:016x}",
        secondary_tie_breaker
    );
    context.aux_socket.connect(second_public_addr).await?;
    context.aux_socket.send(&socket2_pub).await?;
    socket2_messages.extend(
        receive_stun_window(&context.aux_socket, "socket2/pub", Duration::from_millis(700)).await?,
    );

    println!(
        "[stun] summary socket1 binding_success={}",
        socket1_messages.iter().filter(|msg| msg.is_binding_success()).count()
    );
    println!(
        "[stun] summary socket2 binding_success={}",
        socket2_messages.iter().filter(|msg| msg.is_binding_success()).count()
    );

    let total_success = raw_phase.binding_success_count
        + raw_phase_aux.binding_success_count
        + socket1_messages
            .iter()
            .chain(socket2_messages.iter())
            .filter(|msg| msg.is_binding_success())
            .count();
    if total_success == 0 {
        return Err(anyhow!("No STUN Binding Success responses received"));
    }

    println!("[ok] STUN milestone partial success total_binding_success={total_success}");
    Ok(context)
}

struct RawPunchResult {
    first_response_len: usize,
    followup_count: usize,
    binding_success_count: usize,
}

async fn perform_raw_punch(
    socket: &tokio::net::UdpSocket,
    public_addr: SocketAddr,
    local_addr: SocketAddr,
    request_identify: [u8; 8],
) -> Result<RawPunchResult> {
    let public_v4: SocketAddrV4 = match public_addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(_) => return Err(anyhow!("IPv6 pub addr not supported for raw punch")),
    };
    let local_v4: SocketAddrV4 = match local_addr {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(_) => return Err(anyhow!("IPv6 local addr not supported for raw punch")),
    };

    let cookie = rand::random::<[u8; 4]>();
    let txid = rand::random::<[u8; 12]>();
    let cid_inv: Vec<u8> = request_identify.iter().map(|b| !b).collect();

    socket.connect(public_addr).await?;

    let first = [
        b"\xff\xfe\xff\xe7".to_vec(),
        cookie.to_vec(),
        txid.to_vec(),
        b"\x7f\xd5\xff\xf7".to_vec(),
        cid_inv.clone(),
        b"\xff\xfb\xff\xf7\xff\xfe".to_vec(),
        ip_to_bytes(public_v4),
    ]
    .concat();
    println!("[raw] send1 to={public_addr} hex={}", hex_slice(&first, 128));
    socket.send(&first).await?;

    let mut buf = [0u8; 2048];
    let first_len = timeout(Duration::from_secs(3), socket.recv(&mut buf))
        .await
        .map_err(|_| anyhow!("Timed out waiting for first raw public response"))??;
    let first_response = &buf[..first_len];
    println!(
        "[raw] recv1 from={} len={} hex={}",
        socket
            .peer_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|_| "?".to_string()),
        first_len,
        hex_slice(first_response, 128)
    );
    let mut binding_success_count = 0usize;
    if let Ok(message) = StunMessage::parse_normal_or_inverted(first_response) {
        println!(
            "[raw] recv1 parsed type=0x{:04x} inverted={} role={} source_address={}",
            message.message_type,
            message.inverted,
            format_role(message.role.as_ref()),
            format_socket(message.source_address.as_ref())
        );
        if message.is_binding_success() {
            binding_success_count += 1;
        }
    }
    if first_response.len() < 20 {
        return Err(anyhow!("Raw public response too short: {}", first_response.len()));
    }
    let rtrans_id = &first_response[8..20];

    let second = [
        b"\xfe\xfe\xff\xe7".to_vec(),
        cookie.to_vec(),
        rtrans_id.to_vec(),
        b"\x7f\xd6\xff\xf7".to_vec(),
        cid_inv,
        b"\xff\xfb\xff\xf7\xff\xfe".to_vec(),
        ip_to_bytes(local_v4),
    ]
    .concat();
    println!("[raw] send2 to={public_addr} hex={}", hex_slice(&second, 128));
    socket.send(&second).await?;

    let mut followup_count = 0usize;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(900);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let recv = timeout(remaining, socket.recv(&mut buf)).await;
        let Ok(Ok(n)) = recv else {
            break;
        };
        followup_count += 1;
        println!(
            "[raw] recv_followup#{} from={} len={} hex={}",
            followup_count,
            socket
                .peer_addr()
                .map(|addr| addr.to_string())
                .unwrap_or_else(|_| "?".to_string()),
            n,
            hex_slice(&buf[..n], 128)
        );
        if let Ok(message) = StunMessage::parse_normal_or_inverted(&buf[..n]) {
            println!(
                "[raw] recv_followup#{} parsed type=0x{:04x} inverted={} role={} source_address={}",
                followup_count,
                message.message_type,
                message.inverted,
                format_role(message.role.as_ref()),
                format_socket(message.source_address.as_ref())
            );
            if message.is_binding_success() {
                binding_success_count += 1;
            }
        }
    }

    Ok(RawPunchResult {
        first_response_len: first_len,
        followup_count,
        binding_success_count,
    })
}

async fn receive_stun_window(
    socket: &tokio::net::UdpSocket,
    label: &str,
    duration: Duration,
) -> Result<Vec<StunMessage>> {
    let mut buf = [0u8; 2048];
    let mut parsed = Vec::new();
    let deadline = tokio::time::Instant::now() + duration;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let recv = timeout(remaining, socket.recv(&mut buf)).await;
        let Ok(Ok(n)) = recv else {
            break;
        };
        let from = socket
            .peer_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|_| "?".to_string());
        let data = &buf[..n];
        println!(
            "[stun] recv {label} from={from} len={} hex={}",
            n,
            hex_slice(data, 48)
        );

        match StunMessage::parse_normal_or_inverted(data) {
            Ok(message) => {
                println!(
                    "[stun] recv {label} parsed type=0x{:04x} inverted={} role={} source_address={}",
                    message.message_type,
                    message.inverted,
                    format_role(message.role.as_ref()),
                    format_socket(message.source_address.as_ref())
                );
                parsed.push(message);
            }
            Err(error) => {
                println!("[stun] recv {label} non-stun-or-invalid: {error}, ignoring");
            }
        }
    }

    Ok(parsed)
}

fn ip_to_bytes(addr: SocketAddrV4) -> Vec<u8> {
    let ip = addr.ip().octets();
    let port = addr.port();

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&port.to_be_bytes());
    bytes.extend_from_slice(&ip);
    bytes.into_iter().map(|b| !b).collect()
}

#[cfg(test)]
mod tests {
    use super::ip_to_bytes;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn ip_to_bytes_inverts_port_and_ip() {
        let addr = SocketAddrV4::new(Ipv4Addr::new(138, 84, 34, 42), 16392);
        assert_eq!(
            ip_to_bytes(addr),
            vec![!0x40u8, !0x08u8, !138u8, !84u8, !34u8, !42u8]
        );
    }
}
