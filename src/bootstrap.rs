use crate::{
    channel::{
        decrypt_local_addr, dmss_style_local_addr, parse_server_nat_info, relay_channel_body,
        P2pChannelRequest, ServerNatInfo,
    },
    cloud::{bind_udp, ephemeral_client_id, DhTransport, MAIN_SERVER},
};
use anyhow::{anyhow, Context, Result};
use std::net::IpAddr;
use tokio::{net::UdpSocket, time::{timeout, Duration}};

pub struct BootstrapContext {
    pub main_socket: UdpSocket,
    pub aux_socket: UdpSocket,
    pub main_nat: ServerNatInfo,
    pub aux_nat: ServerNatInfo,
    pub main_identify: [u8; 8],
    pub aux_identify: [u8; 8],
}

pub async fn bootstrap_flow(
    serial: &str,
    device_user: &str,
    device_password: &str,
) -> Result<BootstrapContext> {
    let mut cseq = 0i32;
    let pcs_request_id = format!("{:032x}", rand::random::<u128>());
    let socket = bind_udp().await?;
    socket.connect(MAIN_SERVER).await?;

    println!("[bootstrap] /probe/p2psrv");
    socket.dh_request("/probe/p2psrv", None, &mut cseq).await?;
    let probe = socket.dh_read_raw().await?;
    println!("[ok] {} {}", probe.code, probe.status);

    println!("[bootstrap] /online/p2psrv/{serial}");
    socket
        .dh_request(&format!("/online/p2psrv/{serial}"), None, &mut cseq)
        .await?;
    let p2psrv = socket.dh_read_raw().await?;
    let p2psrv_body = p2psrv.body.context("Missing /online/p2psrv body")?;
    let p2psrv_us = p2psrv_body
        .get("body/US")
        .cloned()
        .ok_or_else(|| anyhow!("Missing body/US"))?;
    let p2psrv_ds = p2psrv_body
        .get("body/DS")
        .cloned()
        .ok_or_else(|| anyhow!("Missing body/DS"))?;
    println!("[ok] DS={p2psrv_ds} US={p2psrv_us}");

    println!("[bootstrap] /online/relay");
    socket
        .dh_request_with_headers(
            "/online/relay",
            None,
            &[("x-pcs-request-id", pcs_request_id.as_str())],
            &mut cseq,
        )
        .await?;
    let relay = socket.dh_read_raw().await?;
    let relay_addr = relay
        .body
        .context("Missing /online/relay body")?
        .get("body/Address")
        .cloned()
        .ok_or_else(|| anyhow!("Missing body/Address"))?;
    println!("[ok] relay={relay_addr}");

    let socket2 = bind_udp().await?;
    socket2.connect(&p2psrv_us).await?;

    println!("[bootstrap] /probe/device/{serial}");
    socket2
        .dh_request(&format!("/probe/device/{serial}"), None, &mut cseq)
        .await?;
    let probe_device = socket2.dh_read_raw().await?;
    println!("[ok] /probe/device => {} {}", probe_device.code, probe_device.status);

    println!("[bootstrap] /info/device/{serial}");
    socket2
        .dh_request(&format!("/info/device/{serial}"), None, &mut cseq)
        .await?;
    let info_device = socket2.dh_read_raw().await?;
    if let Some(body) = &info_device.body {
        println!(
            "[ok] /info/device => DevVersion={} Info.len={}",
            body.get("body/DevVersion").cloned().unwrap_or_default(),
            body.get("body/Info").map(|s| s.len()).unwrap_or_default()
        );
    }

    let socket_ip = match socket.local_addr()?.ip() {
        IpAddr::V4(addr) => addr,
        IpAddr::V6(_) => return Err(anyhow!("IPv6 is not supported for DMSS local address")),
    };
    let socket2_ip = match socket2.local_addr()?.ip() {
        IpAddr::V4(addr) => addr,
        IpAddr::V6(_) => return Err(anyhow!("IPv6 is not supported for DMSS local address")),
    };
    let main_request = P2pChannelRequest {
        serial: serial.to_string(),
        username: device_user.to_string(),
        password: device_password.to_string(),
        identify: rand::random::<[u8; 8]>(),
        local_addr: dmss_style_local_addr(socket_ip, socket2_ip, socket.local_addr()?.port()),
        client_id: ephemeral_client_id(37777),
    };
    let aux_request = P2pChannelRequest {
        serial: serial.to_string(),
        username: device_user.to_string(),
        password: device_password.to_string(),
        identify: rand::random::<[u8; 8]>(),
        local_addr: dmss_style_local_addr(socket_ip, socket2_ip, socket2.local_addr()?.port()),
        client_id: ephemeral_client_id(37777),
    };

    socket2.connect(MAIN_SERVER).await?;
    println!("[bootstrap] /device/{serial}/p2p-channel (main)");
    let main_nat = request_p2p_channel(
        &socket,
        serial,
        device_user,
        device_password,
        pcs_request_id.as_str(),
        &mut cseq,
        &main_request,
    )
    .await?;

    println!("[bootstrap] /device/{serial}/p2p-channel (aux)");
    let aux_nat = request_p2p_channel(
        &socket2,
        serial,
        device_user,
        device_password,
        pcs_request_id.as_str(),
        &mut cseq,
        &aux_request,
    )
    .await?;

    socket2.connect(&relay_addr).await?;
    println!("[bootstrap] /relay/agent");
    let relay_agent_body = format!("<body><Dev>{serial}</Dev></body>");
    socket2
        .dh_request_with_headers(
            "/relay/agent",
            Some(&relay_agent_body),
            &[("x-pcs-request-id", pcs_request_id.as_str())],
            &mut cseq,
        )
        .await?;
    let relay_agent = socket2.dh_read_raw().await?;
    let relay_agent_body = relay_agent.body.context("Missing /relay/agent body")?;
    let token = relay_agent_body
        .get("body/Token")
        .cloned()
        .ok_or_else(|| anyhow!("Missing relay token"))?;
    let agent = relay_agent_body
        .get("body/Agent")
        .cloned()
        .ok_or_else(|| anyhow!("Missing relay agent"))?;
    println!("[ok] agent={agent} token={token}");

    socket2.connect(&agent).await?;
    println!("[bootstrap] /relay/start/{token}");
    socket2
        .dh_request_with_headers(
            &format!("/relay/start/{token}"),
            Some("<body><Client>:0</Client></body>"),
            &[("x-pcs-request-id", pcs_request_id.as_str())],
            &mut cseq,
        )
        .await?;
    let relay_start = socket2.dh_read_raw().await?;
    println!("[ok] relay/start => {} {}", relay_start.code, relay_start.status);

    socket2.connect(MAIN_SERVER).await?;
    println!("[bootstrap] /device/{serial}/relay-channel");
    let relay_body = relay_channel_body(device_user, device_password, main_nat.nonce, &agent)?;
    socket2
        .dh_request_with_headers(
            &format!("/device/{serial}/relay-channel"),
            Some(&relay_body),
            &[("x-pcs-request-id", pcs_request_id.as_str())],
            &mut cseq,
        )
        .await?;
    socket2.connect(&agent).await?;
    let relay_channel = socket2.dh_read_raw().await?;
    println!(
        "[ok] relay-channel => {} {}",
        relay_channel.code, relay_channel.status
    );

    print_nat_info("main", &main_nat);
    print_nat_info("aux", &aux_nat);

    Ok(BootstrapContext {
        main_socket: socket,
        aux_socket: socket2,
        main_nat,
        aux_nat,
        main_identify: main_request.identify,
        aux_identify: aux_request.identify,
    })
}

async fn request_p2p_channel(
    socket: &UdpSocket,
    serial: &str,
    device_user: &str,
    device_password: &str,
    pcs_request_id: &str,
    cseq: &mut i32,
    request: &P2pChannelRequest,
) -> Result<ServerNatInfo> {
    let body = request.body()?;
    println!("[debug] p2p-channel local_addr={}", request.local_addr);
    println!("[debug] p2p-channel client_id={}", request.client_id);
    println!(
        "[debug] p2p-channel identify={}",
        request
            .identify
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ")
    );
    println!("[debug] p2p-channel body={body}");
    socket
        .dh_request_with_headers(
            &format!("/device/{serial}/p2p-channel"),
            Some(&body),
            &[("x-pcs-request-id", pcs_request_id)],
            cseq,
        )
        .await?;

    let mut response = timeout(Duration::from_secs(12), socket.dh_read_raw())
        .await
        .map_err(|_| anyhow!("Timed out waiting for first p2p-channel response"))??;
    println!(
        "[debug] p2p-channel first response={} {} headers={:?} body={:?}",
        response.code, response.status, response.headers, response.body
    );
    if response.code == 100 {
        println!("[info] received 100 Trying");
        response = timeout(Duration::from_secs(12), socket.dh_read_raw())
            .await
            .map_err(|_| anyhow!("Timed out waiting for final p2p-channel response after 100 Trying"))??;
        println!(
            "[debug] p2p-channel final response={} {} headers={:?} body={:?}",
            response.code, response.status, response.headers, response.body
        );
    }

    if response.code >= 400 {
        return Err(anyhow!(
            "p2p-channel failed: {} {}",
            response.code,
            response.status
        ));
    }

    let body = response.body.context("Missing p2p-channel body")?;
    let mut nat = parse_server_nat_info(&body)?;
    if nat.ip_encrypt {
        let nonce = nat
            .nonce
            .ok_or_else(|| anyhow!("Encrypted LocalAddr missing Nonce"))?;
        nat.local_addr = decrypt_local_addr(device_user, device_password, nonce, &nat.local_addr)?;
    }
    Ok(nat)
}

fn print_nat_info(label: &str, nat: &ServerNatInfo) {
    println!("[ok] Server Nat Info ({label}):");
    println!("  identify = {}", nat.identify);
    println!("  local_addr = {}", nat.local_addr);
    println!("  pub_addr = {}", nat.pub_addr);
    println!("  policy = {}", nat.policy.clone().unwrap_or_default());
    println!("  relay = {}", nat.relay.clone().unwrap_or_default());
    println!("  version = {}", nat.version.clone().unwrap_or_default());
    println!("  nat_value_t = {}", nat.nat_value_t.unwrap_or_default());
}
