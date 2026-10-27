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

/// Split an encrypted submission's plaintext into header and tar bytes.
pub fn split_submission(plain: &[u8]) -> anyhow::Result<(SubmissionHeader, &[u8])> {
    let rest = plain
        .strip_prefix(SUBMISSION_MAGIC)
        .ok_or_else(|| anyhow::anyhow!("not an attest submission"))?;
    anyhow::ensure!(rest.len() >= 8, "truncated submission");
    let len = u64::from_le_bytes(rest[..8].try_into().unwrap()) as usize;
    anyhow::ensure!(rest.len() >= 8 + len, "truncated submission header");
    let header: SubmissionHeader = serde_json::from_slice(&rest[8..8 + len])?;
    Ok((header, &rest[8 + len..]))
}

pub fn join_submission(header: &SubmissionHeader, tar: &[u8]) -> anyhow::Result<Vec<u8>> {
    let h = serde_json::to_vec(header)?;
    let mut out = Vec::with_capacity(SUBMISSION_MAGIC.len() + 8 + h.len() + tar.len());
    out.extend_from_slice(SUBMISSION_MAGIC);
    out.extend_from_slice(&(h.len() as u64).to_le_bytes());
    out.extend_from_slice(&h);
    out.extend_from_slice(tar);
    Ok(out)
}
