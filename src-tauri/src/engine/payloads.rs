use anyhow::Result;
use rand::RngCore;
use std::fs;
use std::path::{Path, PathBuf};

/// Generate fake QUIC initial packet (standard QUIC Initial packet for google.com).
/// Matches Flowseal's quic_initial_www_google_com.bin.
pub fn generate_fake_quic_initial() -> Vec<u8> {
    let mut buf = vec![0u8; 256];
    let mut offset = 0;

    // Flags: Long Header, Initial packet type (0xc3)
    buf[offset] = 0xc3;
    offset += 1;

    // Version: QUIC v1 (0x00000001)
    buf[offset..offset + 4].copy_from_slice(&1u32.to_be_bytes());
    offset += 4;

    // DCID Length (8) + 8 random bytes
    buf[offset] = 0x08;
    offset += 1;
    rand::thread_rng().fill_bytes(&mut buf[offset..offset + 8]);
    offset += 8;

    // SCID Length (0)
    buf[offset] = 0x00;
    offset += 1;

    // Token Length (0)
    buf[offset] = 0x00;
    offset += 1;

    // Length (2 bytes)
    let remaining = 256 - offset - 2;
    let len_field = (0x4000 | remaining as u16).to_be_bytes();
    buf[offset..offset + 2].copy_from_slice(&len_field);
    offset += 2;

    // Packet Number (4 bytes)
    buf[offset..offset + 4].copy_from_slice(&1u32.to_be_bytes());
    offset += 4;

    // Fill the rest with random data to simulate encrypted payload
    rand::thread_rng().fill_bytes(&mut buf[offset..]);

    buf
}

/// Generate fake TLS ClientHello packet with a custom SNI (Server Name Indication).
/// Matches Flowseal's tls_clienthello_*.bin files.
pub fn generate_fake_tls_client_hello(sni: &str) -> Vec<u8> {
    let sni_bytes = sni.as_bytes();

    // 1. Build SNI extension
    let mut sni_extension = Vec::new();
    // Extension Type: server_name (0x0000)
    sni_extension.extend_from_slice(&0x0000u16.to_be_bytes());
    // Extension Data Length (5 + hostname length)
    let ext_len = (5 + sni_bytes.len()) as u16;
    sni_extension.extend_from_slice(&ext_len.to_be_bytes());
    // Server Name List Length (3 + hostname length)
    let list_len = (3 + sni_bytes.len()) as u16;
    sni_extension.extend_from_slice(&list_len.to_be_bytes());
    // Server Name Type: host_name (0x00)
    sni_extension.push(0x00);
    // Host Name Length
    let host_len = sni_bytes.len() as u16;
    sni_extension.extend_from_slice(&host_len.to_be_bytes());
    // Host Name
    sni_extension.extend_from_slice(sni_bytes);

    // 2. Build ClientHello body
    let mut client_hello_body = Vec::new();
    // TLS Version: TLS 1.2 (0x0303)
    client_hello_body.extend_from_slice(&[0x03, 0x03]);

    // 32 Random bytes
    let mut random = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut random);
    client_hello_body.extend_from_slice(&random);

    // Session ID length: 0
    client_hello_body.push(0x00);

    // Cipher Suites: TLS_AES_128_GCM_SHA256 (0x1301), TLS_AES_256_GCM_SHA384 (0x1302)
    client_hello_body.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]);

    // Compression Methods: 1 method (null: 0x00)
    client_hello_body.extend_from_slice(&[0x01, 0x00]);

    // Extensions length + extension data
    let extensions_len = sni_extension.len() as u16;
    client_hello_body.extend_from_slice(&extensions_len.to_be_bytes());
    client_hello_body.extend_from_slice(&sni_extension);

    // 3. Build Handshake header
    let mut handshake = Vec::new();
    handshake.push(0x01); // Handshake Type: ClientHello
    let body_len = client_hello_body.len() as u32;
    // 3-byte length
    handshake.push(((body_len >> 16) & 0xFF) as u8);
    handshake.push(((body_len >> 8) & 0xFF) as u8);
    handshake.push((body_len & 0xFF) as u8);
    handshake.extend_from_slice(&client_hello_body);

    // 4. Build TLS Record Layer
    let mut record = Vec::new();
    record.push(0x16); // Content Type: Handshake
    record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record layer
    let handshake_len = handshake.len() as u16;
    record.extend_from_slice(&handshake_len.to_be_bytes());
    record.extend_from_slice(&handshake);

    record
}

/// Generate a standard STUN Binding Request packet (for Discord Voice / WebRTC desync).
pub fn generate_fake_stun() -> Vec<u8> {
    let mut packet = vec![0u8; 20];
    // Message Type: Binding Request (0x0001)
    packet[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
    // Message Length: 0x0000 (no attributes)
    packet[2..4].copy_from_slice(&0x0000u16.to_be_bytes());
    // Magic Cookie: 0x2112A442 (fixed RFC 5389)
    packet[4..8].copy_from_slice(&0x2112A442u32.to_be_bytes());
    // 12-byte random Transaction ID
    rand::thread_rng().fill_bytes(&mut packet[8..20]);
    packet
}

/// Ensure all standard fake payload pattern files exist in the specified directory.
pub fn ensure_payload_files(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)?;

    let files: [(&str, Box<dyn Fn() -> Vec<u8>>); 4] = [
        ("quic_initial_www_google_com.bin", Box::new(generate_fake_quic_initial)),
        ("tls_clienthello_www_google_com.bin", Box::new(|| generate_fake_tls_client_hello("www.google.com"))),
        ("tls_clienthello_4pda_to.bin", Box::new(|| generate_fake_tls_client_hello("4pda.to"))),
        ("tls_clienthello_max_ru.bin", Box::new(|| generate_fake_tls_client_hello("max.ru"))),
    ];

    for (name, generator) in files {
        let path = dir.join(name);
        if !path.exists() {
            fs::write(&path, generator())?;
        }
    }

    Ok(())
}

pub struct PayloadManager {
    payloads_dir: PathBuf,
}

impl PayloadManager {
    pub fn new(base_dir: &Path) -> Self {
        let platform_sub = if cfg!(target_os = "macos") {
            "darwin"
        } else if cfg!(target_os = "windows") {
            "win32"
        } else {
            "linux"
        };
        Self {
            payloads_dir: base_dir.join("bin").join(platform_sub),
        }
    }

    pub fn ensure_payloads(&self) -> Result<()> {
        ensure_payload_files(&self.payloads_dir)
    }
}
