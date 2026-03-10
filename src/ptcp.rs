use std::cmp;

#[derive(Debug, Clone)]
pub struct PtcpPayload {
    pub realm: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum PtcpBody {
    Sync,
    Payload(PtcpPayload),
    Bind {
        realm: u32,
        port: u32,
        ip: [u8; 4],
    },
    Status { realm: u32, status: String },
    Heartbeat,
    Command(Vec<u8>),
    Empty,
}

#[derive(Debug, Clone)]
pub struct PtcpPacket {
    pub sent: u32,
    pub recv: u32,
    pub pid: u32,
    pub lmid: u32,
    pub rmid: u32,
    pub body: PtcpBody,
}

impl PtcpPayload {
    pub fn preview(&self) -> String {
        self.data[0..cmp::min(self.data.len(), 16)]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl PtcpPacket {
    pub fn parse(data: &[u8]) -> anyhow::Result<Self> {
        anyhow::ensure!(data.len() >= 24, "Invalid PTCP packet");
        anyhow::ensure!(&data[0..4] == b"PTCP", "Invalid PTCP magic");

        let sent = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let recv = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let pid = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let lmid = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let rmid = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
        let body = parse_body(&data[24..])?;

        Ok(Self {
            sent,
            recv,
            pid,
            lmid,
            rmid,
            body,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        [
            b"PTCP".to_vec(),
            self.sent.to_be_bytes().to_vec(),
            self.recv.to_be_bytes().to_vec(),
            self.pid.to_be_bytes().to_vec(),
            self.lmid.to_be_bytes().to_vec(),
            self.rmid.to_be_bytes().to_vec(),
            self.body.serialize(),
        ]
        .concat()
    }
}

fn parse_body(data: &[u8]) -> anyhow::Result<PtcpBody> {
    if data.is_empty() {
        return Ok(PtcpBody::Empty);
    }
    anyhow::ensure!(data.len() >= 4, "Invalid PTCP body");

    Ok(match data[0] {
        0x00 => PtcpBody::Sync,
        0x10 => {
            anyhow::ensure!(data.len() >= 12, "Invalid PTCP payload");
            let header = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            let length = header & 0xFFFF;
            let realm = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            let payload = data[12..].to_vec();
            anyhow::ensure!(length == payload.len() as u32, "Invalid PTCP payload length");
            PtcpBody::Payload(PtcpPayload { realm, data: payload })
        }
        0x11 => PtcpBody::Bind {
            realm: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            port: u32::from_be_bytes([data[12], data[13], data[14], data[15]]),
            ip: [data[16], data[17], data[18], data[19]],
        },
        0x12 => PtcpBody::Status {
            realm: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            status: String::from_utf8_lossy(&data[12..]).to_string(),
        },
        0x13 => PtcpBody::Heartbeat,
        _ => PtcpBody::Command(data.to_vec()),
    })
}

impl PtcpBody {
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            PtcpBody::Sync => b"\x00\x03\x01\x00".to_vec(),
            PtcpBody::Payload(payload) => payload.serialize(),
            PtcpBody::Bind { realm, port, ip } => [
                b"\x11\x00\x00\x08".to_vec(),
                realm.to_be_bytes().to_vec(),
                b"\x00\x00\x00\x00".to_vec(),
                port.to_be_bytes().to_vec(),
                ip.to_vec(),
            ]
            .concat(),
            PtcpBody::Status { realm, status } => [
                vec![0x12, 0x00, ((status.len() >> 8) & 0xff) as u8, (status.len() & 0xff) as u8],
                realm.to_be_bytes().to_vec(),
                b"\x00\x00\x00\x00".to_vec(),
                status.as_bytes().to_vec(),
            ]
            .concat(),
            PtcpBody::Heartbeat => {
                b"\x13\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec()
            }
            PtcpBody::Command(data) => data.clone(),
            PtcpBody::Empty => Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            PtcpBody::Sync => 4,
            PtcpBody::Payload(payload) => payload.data.len() + 12,
            PtcpBody::Bind { .. } => 20,
            PtcpBody::Status { status, .. } => status.len() + 12,
            PtcpBody::Heartbeat => 12,
            PtcpBody::Command(data) => data.len(),
            PtcpBody::Empty => 0,
        }
    }
}

impl PtcpPayload {
    pub fn serialize(&self) -> Vec<u8> {
        let length = self.data.len() as u32;
        let header = 0x10000000u32 | length;
        [
            header.to_be_bytes().to_vec(),
            self.realm.to_be_bytes().to_vec(),
            0u32.to_be_bytes().to_vec(),
            self.data.clone(),
        ]
        .concat()
    }
}

#[derive(Debug, Clone)]
pub struct PtcpSession {
    sent: u32,
    recv: u32,
    count: u32,
    id: u32,
    rmid: u32,
}

impl PtcpSession {
    pub fn new() -> Self {
        Self {
            sent: 0,
            recv: 0,
            count: 0,
            id: 0,
            rmid: 0,
        }
    }

    pub fn send(&mut self, body: PtcpBody) -> PtcpPacket {
        let sent = self.sent;
        let recv = self.recv;
        let pid = match body {
            PtcpBody::Sync => 0x0002FFFF,
            _ => 0x0000FFFF - self.count,
        };
        let lmid = self.id;
        let rmid = self.rmid;

        self.sent += body.len() as u32;
        self.id += 1;
        self.count += match body {
            PtcpBody::Sync | PtcpBody::Empty => 0,
            _ => 1,
        };

        PtcpPacket {
            sent,
            recv,
            pid,
            lmid,
            rmid,
            body,
        }
    }

    pub fn recv(&mut self, packet: &PtcpPacket) {
        self.recv += packet.body.len() as u32;
        self.rmid = packet.lmid;
    }
}
