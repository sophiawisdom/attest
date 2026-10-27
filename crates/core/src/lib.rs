pub mod harness;
pub mod nitro;
pub mod scan;
pub mod sign;
pub mod tree;
pub mod types;
pub mod verify;

pub use types::*;

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    tree::sha256(bytes)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(sha256(bytes))
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// sha256 hex of a DER certificate's SubjectPublicKeyInfo.
pub fn spki_sha256_of_cert(der: &[u8]) -> anyhow::Result<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|e| anyhow::anyhow!("certificate: {e}"))?;
    Ok(sha256_hex(cert.public_key().raw))
}
