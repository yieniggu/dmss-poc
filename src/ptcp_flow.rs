use crate::{
    bootstrap::BootstrapContext,
    login::{AuthHashStrategy, LoginAccepted, LoginChallenge, LoginResponse},
    logging::hex_slice,
    play::{persist_media_capture, PlayRequest, PlayResponseFrame},
    ptcp::{PtcpBody, PtcpPacket, PtcpSession},
};
use anyhow::{anyhow, Context, Result};
use std::net::SocketAddr;
use tokio::time::{timeout, Duration};

const PRE_LOGIN_REALM: u32 = 0xedff72f0;
const MEDIA_REALM: u32 = 0xffbc55fa;
const LOOPBACK_IP: [u8; 4] = [127, 0, 0, 1];
const DEVICE_CONTROL_PORT: u32 = 37777;
const MEDIA_BIND_PORT: u32 = 554;
const DEFAULT_PLAY_CHANNEL: u32 = 1;
const DEFAULT_PLAY_SUBTYPE: u8 = 1;
const MEDIA_CAPTURE_CHUNKS: usize = 8;
const MEDIA_CAPTURE_TIMEOUT_MS: u64 = 400;
const PRE_LOGIN_PAYLOAD: [u8; 32] = [
    0xa0, 0x05, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x09, 0x01, 0x00, 0x00,
    0xa1, 0xaa,
];

pub async fn perform_ptcp_sync(context: BootstrapContext) -> Result<()> {
    perform_ptcp_sync_with_credentials(context, "admin", "")
        .await
        .context("Internal PTCP entrypoint should not be used without credentials")
}

pub async fn perform_ptcp_sync_with_credentials(
    context: BootstrapContext,
    device_user: &str,
    device_password: &str,
) -> Result<()> {
    let main_host_port = context.aux_socket.local_addr()?.port();
    let aux_host_port = context.main_socket.local_addr()?.port();
    let main_pub_addr: SocketAddr = context
        .main_nat
        .pub_addr
        .parse()
        .with_context(|| format!("Invalid main PubAddr {}", context.main_nat.pub_addr))?;
    let aux_pub_addr: SocketAddr = context
        .aux_nat
        .pub_addr
        .parse()
        .with_context(|| format!("Invalid aux PubAddr {}", context.aux_nat.pub_addr))?;

    match try_ptcp_sync(
        &context.main_socket,
        main_pub_addr,
        "main/pub",
        AuthHashStrategy::PrefixPlusHa1,
        device_user,
        device_password,
        main_host_port,
    )
    .await
    {
        Ok(()) => return Ok(()),
        Err(error) => println!("[ptcp] main/pub failed: {error}"),
    }
    match try_ptcp_sync(
        &context.aux_socket,
        aux_pub_addr,
        "aux/pub",
        AuthHashStrategy::PrefixPlusMd5Ha1Random,
        device_user,
        device_password,
        aux_host_port,
    )
    .await
    {
        Ok(()) => return Ok(()),
        Err(error) => println!("[ptcp] aux/pub failed: {error}"),
    }

    Err(anyhow!("PTCP sync failed on both public channels"))
}

async fn try_ptcp_sync(
    socket: &tokio::net::UdpSocket,
    target: SocketAddr,
    label: &str,
    auth_strategy: AuthHashStrategy,
    device_user: &str,
    device_password: &str,
    host_port: u16,
) -> Result<()> {
    socket.connect(target).await?;

    let mut session = PtcpSession::new();
    let sync = session.send(PtcpBody::Sync);
    println!(
        "[ptcp] send sync {label} to={} sent={} recv={} pid=0x{:08x} lmid=0x{:08x} rmid=0x{:08x}",
        target, sync.sent, sync.recv, sync.pid, sync.lmid, sync.rmid
    );
    socket.send(&sync.serialize()).await?;

    let mut buf = [0u8; 4096];
    let n = timeout(Duration::from_secs(3), socket.recv(&mut buf))
        .await
        .map_err(|_| anyhow!("Timed out waiting for PTCP sync response"))??;
    println!("[ptcp] recv {label} len={} hex={}", n, hex_slice(&buf[..n], 128));

    let packet = PtcpPacket::parse(&buf[..n]).context("Failed to parse PTCP sync response")?;
    println!(
        "[ptcp] recv {label} parsed sent={} recv={} pid=0x{:08x} lmid=0x{:08x} rmid=0x{:08x} body={:?}",
        packet.sent, packet.recv, packet.pid, packet.lmid, packet.rmid, packet.body
    );
    session.recv(&packet);

    if !matches!(packet.body, PtcpBody::Sync) {
        return Err(anyhow!("PTCP sync response was not Sync"));
    }

    println!("[ok] PTCP sync milestone success on {label}");

    let init = session.send(PtcpBody::Command(
        b"\x17\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
    ));
    println!(
        "[ptcp] send init {label} sent={} recv={} pid=0x{:08x} lmid=0x{:08x} rmid=0x{:08x} hex={}",
        init.sent,
        init.recv,
        init.pid,
        init.lmid,
        init.rmid,
        hex_slice(&init.serialize(), 128)
    );
    socket.send(&init.serialize()).await?;

    loop {
        let n = timeout(Duration::from_secs(3), socket.recv(&mut buf))
            .await
            .map_err(|_| anyhow!("Timed out waiting for PTCP init response"))??;
        println!(
            "[ptcp] recv init {label} len={} hex={}",
            n,
            hex_slice(&buf[..n], 128)
        );

        let packet = PtcpPacket::parse(&buf[..n]).context("Failed to parse PTCP init response")?;
        println!(
            "[ptcp] recv init {label} parsed sent={} recv={} pid=0x{:08x} lmid=0x{:08x} rmid=0x{:08x} body={:?}",
            packet.sent, packet.recv, packet.pid, packet.lmid, packet.rmid, packet.body
        );
        session.recv(&packet);

        match &packet.body {
            PtcpBody::Empty => continue,
            PtcpBody::Command(data) => {
                anyhow::ensure!(
                    data.len() >= 12,
                    "PTCP init command response too short: {}",
                    data.len()
                );
                let sign = &data[12..];
                println!("[ptcp] init sign {label}={}", hex_slice(sign, 128));
                println!("[ok] PTCP init milestone success on {label}");
                return complete_post_init(
                    socket,
                    label,
                    &mut session,
                    &mut buf,
                    sign,
                    auth_strategy,
                    device_user,
                    device_password,
                    host_port,
                )
                .await;
            }
            other => {
                return Err(anyhow!("Unexpected PTCP init response body: {:?}", other));
            }
        }
    }
}

async fn complete_post_init(
    socket: &tokio::net::UdpSocket,
    label: &str,
    session: &mut PtcpSession,
    buf: &mut [u8; 4096],
    sign: &[u8],
    auth_strategy: AuthHashStrategy,
    device_user: &str,
    device_password: &str,
    host_port: u16,
) -> Result<()> {
    let command_19 = session.send(PtcpBody::Command(
        [
            b"\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
            sign.to_vec(),
        ]
        .concat(),
    ));
    println!(
        "[ptcp] send 0x19 {label} sent={} recv={} pid=0x{:08x} lmid=0x{:08x} rmid=0x{:08x} hex={}",
        command_19.sent,
        command_19.recv,
        command_19.pid,
        command_19.lmid,
        command_19.rmid,
        hex_slice(&command_19.serialize(), 160)
    );
    socket.send(&command_19.serialize()).await?;

    loop {
        let n = timeout(Duration::from_secs(3), socket.recv(buf))
            .await
            .map_err(|_| anyhow!("Timed out waiting for PTCP 0x19 response"))??;
        println!(
            "[ptcp] recv 0x19 {label} len={} hex={}",
            n,
            hex_slice(&buf[..n], 160)
        );

        let packet = PtcpPacket::parse(&buf[..n]).context("Failed to parse PTCP 0x19 response")?;
        println!(
            "[ptcp] recv 0x19 {label} parsed sent={} recv={} pid=0x{:08x} lmid=0x{:08x} rmid=0x{:08x} body={:?}",
            packet.sent, packet.recv, packet.pid, packet.lmid, packet.rmid, packet.body
        );
        session.recv(&packet);

        match &packet.body {
            PtcpBody::Empty => continue,
            PtcpBody::Command(data) => {
                anyhow::ensure!(!data.is_empty(), "PTCP 0x19 command response had empty payload");
                println!(
                    "[ptcp] 0x19 response first_byte=0x{:02x} payload={}",
                    data[0],
                    hex_slice(data, 160)
                );
                anyhow::ensure!(
                    data[0] == 0x1A,
                    "Expected PTCP 0x1A response, got 0x{:02x}",
                    data[0]
                );
                println!("[ok] PTCP 0x19 milestone success on {label}");
                return complete_1b(
                    socket,
                    label,
                    session,
                    buf,
                    auth_strategy,
                    device_user,
                    device_password,
                    host_port,
                )
                .await;
            }
            other => {
                return Err(anyhow!("Unexpected PTCP 0x19 response body: {:?}", other));
            }
        }
    }
}

async fn complete_1b(
    socket: &tokio::net::UdpSocket,
    label: &str,
    session: &mut PtcpSession,
    buf: &mut [u8; 4096],
    auth_strategy: AuthHashStrategy,
    device_user: &str,
    device_password: &str,
    host_port: u16,
) -> Result<()> {
    let command_1b = session.send(PtcpBody::Command(
        b"\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
    ));
    println!(
        "[ptcp] send 0x1b {label} sent={} recv={} pid=0x{:08x} lmid=0x{:08x} rmid=0x{:08x} hex={}",
        command_1b.sent,
        command_1b.recv,
        command_1b.pid,
        command_1b.lmid,
        command_1b.rmid,
        hex_slice(&command_1b.serialize(), 160)
    );
    socket.send(&command_1b.serialize()).await?;

    let n = timeout(Duration::from_secs(3), socket.recv(buf))
        .await
        .map_err(|_| anyhow!("Timed out waiting for PTCP 0x1b response"))??;
    println!(
        "[ptcp] recv 0x1b {label} len={} hex={}",
        n,
        hex_slice(&buf[..n], 160)
    );
    let packet = PtcpPacket::parse(&buf[..n]).context("Failed to parse PTCP 0x1b response")?;
    println!(
        "[ptcp] recv 0x1b {label} parsed sent={} recv={} pid=0x{:08x} lmid=0x{:08x} rmid=0x{:08x} body={:?}",
        packet.sent, packet.recv, packet.pid, packet.lmid, packet.rmid, packet.body
    );
    session.recv(&packet);
    anyhow::ensure!(
        matches!(packet.body, PtcpBody::Empty),
        "Expected PTCP Empty after 0x1b, got {:?}",
        packet.body
    );
    println!("[ok] PTCP 0x1b milestone success on {label}");
    complete_pre_login(
        socket,
        label,
        session,
        buf,
        auth_strategy,
        device_user,
        device_password,
        host_port,
    )
    .await
}

async fn complete_pre_login(
    socket: &tokio::net::UdpSocket,
    label: &str,
    session: &mut PtcpSession,
    buf: &mut [u8; 4096],
    auth_strategy: AuthHashStrategy,
    device_user: &str,
    device_password: &str,
    host_port: u16,
) -> Result<()> {
    let heartbeat = session.send(PtcpBody::Heartbeat);
    println!(
        "[ptcp] send heartbeat {label} sent={} recv={} pid=0x{:08x} lmid=0x{:08x} rmid=0x{:08x} hex={}",
        heartbeat.sent,
        heartbeat.recv,
        heartbeat.pid,
        heartbeat.lmid,
        heartbeat.rmid,
        hex_slice(&heartbeat.serialize(), 160)
    );
    socket.send(&heartbeat.serialize()).await?;

    let bind = session.send(PtcpBody::Bind {
        realm: PRE_LOGIN_REALM,
        port: DEVICE_CONTROL_PORT,
        ip: LOOPBACK_IP,
    });
    println!(
        "[ptcp] send bind {label} sent={} recv={} pid=0x{:08x} lmid=0x{:08x} rmid=0x{:08x} hex={}",
        bind.sent,
        bind.recv,
        bind.pid,
        bind.lmid,
        bind.rmid,
        hex_slice(&bind.serialize(), 160)
    );
    socket.send(&bind.serialize()).await?;

    loop {
        let n = timeout(Duration::from_secs(3), socket.recv(buf))
            .await
            .map_err(|_| anyhow!("Timed out waiting for PTCP CONN status"))??;
        println!(
            "[ptcp] recv bind {label} len={} hex={}",
            n,
            hex_slice(&buf[..n], 160)
        );
        let packet = PtcpPacket::parse(&buf[..n]).context("Failed to parse PTCP bind response")?;
        println!(
            "[ptcp] recv bind {label} parsed sent={} recv={} pid=0x{:08x} lmid=0x{:08x} rmid=0x{:08x} body={:?}",
            packet.sent, packet.recv, packet.pid, packet.lmid, packet.rmid, packet.body
        );
        session.recv(&packet);

        match &packet.body {
            PtcpBody::Heartbeat | PtcpBody::Empty => continue,
            PtcpBody::Status { realm, status } => {
                anyhow::ensure!(
                    *realm == PRE_LOGIN_REALM,
                    "Unexpected bind realm: 0x{realm:08x}"
                );
                anyhow::ensure!(status == "CONN", "Unexpected PTCP bind status: {status}");
                println!("[ok] PTCP bind milestone success on {label}");
                break;
            }
            other => {
                return Err(anyhow!("Unexpected PTCP bind response body: {:?}", other));
            }
        }
    }

    let payload = session.send(PtcpBody::Payload(crate::ptcp::PtcpPayload {
        realm: PRE_LOGIN_REALM,
        data: PRE_LOGIN_PAYLOAD.to_vec(),
    }));
    println!(
        "[ptcp] send pre-login payload {label} sent={} recv={} pid=0x{:08x} lmid=0x{:08x} rmid=0x{:08x} hex={}",
        payload.sent,
        payload.recv,
        payload.pid,
        payload.lmid,
        payload.rmid,
        hex_slice(&payload.serialize(), 192)
    );
    socket.send(&payload.serialize()).await?;

    let challenge = await_login_challenge(socket, label, session, buf).await?;
    complete_login_auth(
        socket,
        label,
        session,
        buf,
        &challenge,
        auth_strategy,
        device_user,
        device_password,
        host_port,
    )
    .await
}

async fn await_login_challenge(
    socket: &tokio::net::UdpSocket,
    label: &str,
    session: &mut PtcpSession,
    buf: &mut [u8; 4096],
) -> Result<LoginChallenge> {
    loop {
        let n = timeout(Duration::from_secs(3), socket.recv(buf))
            .await
            .map_err(|_| anyhow!("Timed out waiting for PTCP login challenge"))??;
        println!(
            "[ptcp] recv login {label} len={} hex={}",
            n,
            hex_slice(&buf[..n], 192)
        );
        let packet = PtcpPacket::parse(&buf[..n]).context("Failed to parse PTCP login challenge")?;
        println!(
            "[ptcp] recv login {label} parsed sent={} recv={} pid=0x{:08x} lmid=0x{:08x} rmid=0x{:08x} body={:?}",
            packet.sent, packet.recv, packet.pid, packet.lmid, packet.rmid, packet.body
        );
        session.recv(&packet);

        match &packet.body {
            PtcpBody::Empty | PtcpBody::Heartbeat => continue,
            PtcpBody::Payload(payload) => {
                println!(
                    "[ptcp] login payload {label} realm=0x{:08x} preview={}",
                    payload.realm,
                    payload.preview()
                );
                if let Some(challenge) = LoginChallenge::parse_bytes(&payload.data) {
                    println!(
                        "[ptcp] login challenge {label} realm_label={} random={}",
                        challenge.realm_label, challenge.random
                    );
                    println!("[ok] PTCP login challenge milestone success on {label}");
                    return Ok(challenge);
                }
                return Err(anyhow!(
                    "PTCP login payload did not contain Realm/Random text"
                ));
            }
            PtcpBody::Command(data) => {
                if let Some(challenge) = LoginChallenge::parse_bytes(data) {
                    println!(
                        "[ptcp] login command challenge {label} realm_label={} random={}",
                        challenge.realm_label, challenge.random
                    );
                    println!("[ok] PTCP login challenge milestone success on {label}");
                    return Ok(challenge);
                }
                return Err(anyhow!(
                    "Unexpected PTCP command during login challenge: {}",
                    hex_slice(data, 192)
                ));
            }
            other => {
                return Err(anyhow!(
                    "Unexpected PTCP body while waiting for login challenge: {:?}",
                    other
                ));
            }
        }
    }
}

async fn complete_login_auth(
    socket: &tokio::net::UdpSocket,
    label: &str,
    session: &mut PtcpSession,
    buf: &mut [u8; 4096],
    challenge: &LoginChallenge,
    auth_strategy: AuthHashStrategy,
    device_user: &str,
    device_password: &str,
    host_port: u16,
) -> Result<()> {
    let response = LoginResponse::build(device_user, device_password, challenge, auth_strategy);
    let auth_payload = session.send(PtcpBody::Payload(crate::ptcp::PtcpPayload {
        realm: PRE_LOGIN_REALM,
        data: response.payload.clone(),
    }));
    println!(
        "[ptcp] send auth {label} strategy={} sent={} recv={} pid=0x{:08x} lmid=0x{:08x} rmid=0x{:08x}",
        response.strategy.name(),
        auth_payload.sent,
        auth_payload.recv,
        auth_payload.pid,
        auth_payload.lmid,
        auth_payload.rmid
    );
    println!(
        "[ptcp] auth token {label} strategy={} hash64={}",
        response.strategy.name(),
        response.hash64
    );
    println!(
        "[ptcp] auth payload {label} hex={}",
        hex_slice(&auth_payload.serialize(), 256)
    );
    socket.send(&auth_payload.serialize()).await?;

    loop {
        let n = timeout(Duration::from_secs(3), socket.recv(buf))
            .await
            .map_err(|_| anyhow!("Timed out waiting for PTCP auth response"))??;
        println!(
            "[ptcp] recv auth {label} len={} hex={}",
            n,
            hex_slice(&buf[..n], 256)
        );
        let packet = PtcpPacket::parse(&buf[..n]).context("Failed to parse PTCP auth response")?;
        println!(
            "[ptcp] recv auth {label} parsed sent={} recv={} pid=0x{:08x} lmid=0x{:08x} rmid=0x{:08x} body={:?}",
            packet.sent, packet.recv, packet.pid, packet.lmid, packet.rmid, packet.body
        );
        session.recv(&packet);

        match &packet.body {
            PtcpBody::Empty | PtcpBody::Heartbeat => continue,
            PtcpBody::Payload(payload) => {
                if let Some(accepted) = LoginAccepted::parse_bytes(&payload.data) {
                    println!(
                        "[ptcp] login accepted {label} function={} media_encrypt={}",
                        accepted.function, accepted.media_encrypt
                    );
                    println!(
                        "[ok] PTCP login auth milestone success on {label} strategy={}",
                        response.strategy.name()
                    );
                    return complete_stream_open(
                        socket,
                        label,
                        session,
                        buf,
                        challenge,
                        device_user,
                        device_password,
                        host_port,
                    )
                    .await;
                }
                return Err(anyhow!(
                    "PTCP auth payload did not contain Function/MediaEncrypt text"
                ));
            }
            other => {
                return Err(anyhow!(
                    "Unexpected PTCP body while waiting for auth response: {:?}",
                    other
                ));
            }
        }
    }
}

async fn complete_stream_open(
    socket: &tokio::net::UdpSocket,
    label: &str,
    session: &mut PtcpSession,
    buf: &mut [u8; 4096],
    challenge: &LoginChallenge,
    device_user: &str,
    device_password: &str,
    host_port: u16,
) -> Result<()> {
    let media_bind = session.send(PtcpBody::Bind {
        realm: MEDIA_REALM,
        port: MEDIA_BIND_PORT,
        ip: LOOPBACK_IP,
    });
    println!(
        "[ptcp] send media bind {label} sent={} recv={} pid=0x{:08x} lmid=0x{:08x} rmid=0x{:08x} hex={}",
        media_bind.sent,
        media_bind.recv,
        media_bind.pid,
        media_bind.lmid,
        media_bind.rmid,
        hex_slice(&media_bind.serialize(), 160)
    );
    socket.send(&media_bind.serialize()).await?;

    loop {
        let n = timeout(Duration::from_secs(3), socket.recv(buf))
            .await
            .map_err(|_| anyhow!("Timed out waiting for PTCP media CONN status"))??;
        println!(
            "[ptcp] recv media bind {label} len={} hex={}",
            n,
            hex_slice(&buf[..n], 160)
        );
        let packet =
            PtcpPacket::parse(&buf[..n]).context("Failed to parse PTCP media bind response")?;
        println!(
            "[ptcp] recv media bind {label} parsed sent={} recv={} pid=0x{:08x} lmid=0x{:08x} rmid=0x{:08x} body={:?}",
            packet.sent, packet.recv, packet.pid, packet.lmid, packet.rmid, packet.body
        );
        session.recv(&packet);

        match &packet.body {
            PtcpBody::Empty | PtcpBody::Heartbeat => continue,
            PtcpBody::Status { realm, status } => {
                anyhow::ensure!(
                    *realm == MEDIA_REALM,
                    "Unexpected media bind realm: 0x{realm:08x}"
                );
                anyhow::ensure!(status == "CONN", "Unexpected PTCP media bind status: {status}");
                println!("[ok] PTCP media bind milestone success on {label}");
                break;
            }
            other => {
                return Err(anyhow!(
                    "Unexpected PTCP body while waiting for media CONN: {:?}",
                    other
                ));
            }
        }
    }

    let play = PlayRequest {
        channel: DEFAULT_PLAY_CHANNEL,
        subtype: DEFAULT_PLAY_SUBTYPE,
        username: device_user.to_string(),
        password: device_password.to_string(),
        realm_label: challenge.realm_label.clone(),
        host_port,
    };
    let play_http = play.to_http_like();
    let play_payload = session.send(PtcpBody::Payload(crate::ptcp::PtcpPayload {
        realm: MEDIA_REALM,
        data: play_http.as_bytes().to_vec(),
    }));
    println!(
        "[ptcp] send play {label} sent={} recv={} pid=0x{:08x} lmid=0x{:08x} rmid=0x{:08x}",
        play_payload.sent,
        play_payload.recv,
        play_payload.pid,
        play_payload.lmid,
        play_payload.rmid
    );
    println!(
        "[ptcp] play request {label} realm=0x{:08x} host_port={} preview={}",
        MEDIA_REALM,
        host_port,
        hex_slice(play_http.as_bytes(), 256)
    );
    socket.send(&play_payload.serialize()).await?;

    loop {
        let n = timeout(Duration::from_secs(3), socket.recv(buf))
            .await
            .map_err(|_| anyhow!("Timed out waiting for PTCP play response"))??;
        println!(
            "[ptcp] recv play {label} len={} hex={}",
            n,
            hex_slice(&buf[..n], 256)
        );
        let packet = PtcpPacket::parse(&buf[..n]).context("Failed to parse PTCP play response")?;
        println!(
            "[ptcp] recv play {label} parsed sent={} recv={} pid=0x{:08x} lmid=0x{:08x} rmid=0x{:08x} body={:?}",
            packet.sent, packet.recv, packet.pid, packet.lmid, packet.rmid, packet.body
        );
        session.recv(&packet);

        match &packet.body {
            PtcpBody::Empty | PtcpBody::Heartbeat => continue,
            PtcpBody::Payload(payload) => {
                if let Some(frame) = PlayResponseFrame::parse_bytes(&payload.data) {
                    println!(
                        "[ptcp] play response {label} realm=0x{:08x} status={} content_type={} private_type={:?} private_length={:?} session_id={:?}",
                        payload.realm,
                        frame.response.status_line,
                        frame.response.content_type,
                        frame.response.private_type,
                        frame.response.private_length,
                        frame.response.session_id
                    );
                    anyhow::ensure!(
                        payload.realm == MEDIA_REALM,
                        "Unexpected media realm 0x{:08x}",
                        payload.realm
                    );
                    anyhow::ensure!(
                        frame.response.is_success(),
                        "PTCP play response was not 200/e-xav"
                    );
                    let media_chunks = capture_media_chunks(socket, label, session, buf).await?;
                    let summary = persist_media_capture(
                        std::path::Path::new("artifacts"),
                        label,
                        &frame,
                        &media_chunks,
                    )?;
                    println!(
                        "[ptcp] media capture {label} dir={} private_body_len={} media_chunks={} media_bytes={}",
                        summary.output_dir.display(),
                        summary.private_body_len,
                        summary.media_chunk_count,
                        summary.media_bytes
                    );
                    println!("[ok] PTCP play milestone success on {label}");
                    return Ok(());
                }
                return Err(anyhow!("PTCP play payload did not contain HTTP response"));
            }
            other => {
                return Err(anyhow!(
                    "Unexpected PTCP body while waiting for play response: {:?}",
                    other
                ));
            }
        }
    }
}

async fn capture_media_chunks(
    socket: &tokio::net::UdpSocket,
    label: &str,
    session: &mut PtcpSession,
    buf: &mut [u8; 4096],
) -> Result<Vec<Vec<u8>>> {
    let mut media_chunks = Vec::new();

    while media_chunks.len() < MEDIA_CAPTURE_CHUNKS {
        let recv = timeout(Duration::from_millis(MEDIA_CAPTURE_TIMEOUT_MS), socket.recv(buf)).await;
        let n = match recv {
            Ok(Ok(n)) => n,
            Ok(Err(error)) => return Err(error).context("Failed while capturing media chunks"),
            Err(_) => break,
        };

        println!(
            "[ptcp] recv media {label} len={} hex={}",
            n,
            hex_slice(&buf[..n], 192)
        );
        let packet = PtcpPacket::parse(&buf[..n]).context("Failed to parse PTCP media chunk")?;
        println!(
            "[ptcp] recv media {label} parsed sent={} recv={} pid=0x{:08x} lmid=0x{:08x} rmid=0x{:08x} body={:?}",
            packet.sent, packet.recv, packet.pid, packet.lmid, packet.rmid, packet.body
        );
        session.recv(&packet);

        match packet.body {
            PtcpBody::Empty | PtcpBody::Heartbeat => continue,
            PtcpBody::Payload(payload) => {
                if payload.realm != MEDIA_REALM {
                    println!(
                        "[ptcp] skip media payload {label} unexpected_realm=0x{:08x}",
                        payload.realm
                    );
                    continue;
                }
                println!(
                    "[ptcp] media chunk {label} index={} bytes={}",
                    media_chunks.len(),
                    payload.data.len()
                );
                media_chunks.push(payload.data);
            }
            other => {
                println!("[ptcp] skip media body {label} unexpected={:?}", other);
            }
        }
    }

    Ok(media_chunks)
}
