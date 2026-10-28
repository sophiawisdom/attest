//! Durable state, sealed on the parent like uploaded files (blobs.rs).
//!
//! A lineage of enclaves (one image, handing over to each other: see
//! handoff.rs) shares a 32-byte master key, MK, that never leaves enclave
//! memory except encrypted to an attested successor. From MK come:
//!
//!   seal key  ChaCha20-Poly1305 over every state record; the associated
//!             data names the record (session id and record name), so the
//!             parent can't swap one record for another.
//!   id key    blob ids: an 8-byte tag per session (so deleting a session's
//!             records is one delete-by-tag) and 16 bytes per record name,
//!             so a successor finds records without listing anything.
//!
//! Records are overwritten in place, so on its own the store can't tell a
//! current record from an old one the parent kept. Freshness comes from
//! hashes: each session's head record lists the hashes of its snapshot
//! parts and trace chunks, and at a handoff the giver sends the hash of
//! every session's latest head inside the encrypted, attested payload.

use crate::blobs::{pad_blob, unpad_blob, BlobClient, BlobId, MAX_FILE_BYTES};
use anyhow::{anyhow, ensure, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hmac::{Hmac, Mac};

pub use attest_core::LineageInfo as Lineage;

fn prf(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<sha2::Sha256> as Mac>::new_from_slice(key).expect("any key length");
    for p in parts {
        m.update(&(p.len() as u64).to_le_bytes());
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

pub struct Keys {
    mk: [u8; 32],
    seal: ChaCha20Poly1305,
    ids: [u8; 32],
}

impl Keys {
    pub fn new(mk: [u8; 32]) -> Self {
        let seal = prf(&mk, &[b"attest-state-seal/1"]);
        Self {
            mk,
            seal: ChaCha20Poly1305::new(Key::from_slice(&seal)),
            ids: prf(&mk, &[b"attest-state-ids/1"]),
        }
    }

    pub fn generate() -> Self {
        let mut mk = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut mk);
        Self::new(mk)
    }

    /// The master key itself, only for handing to an attested successor.
    pub fn master(&self) -> [u8; 32] {
        self.mk
    }

    pub fn tag(&self, sid: &str) -> [u8; 8] {
        prf(&self.ids, &[b"tag", sid.as_bytes()])[..8].try_into().unwrap()
    }

    pub fn id(&self, sid: &str, name: &str) -> BlobId {
        let mut id = [0u8; 24];
        id[..8].copy_from_slice(&self.tag(sid));
        id[8..].copy_from_slice(&prf(&self.ids, &[b"record", sid.as_bytes(), name.as_bytes()])[..16]);
        id
    }

    fn aad(sid: &str, name: &str) -> Vec<u8> {
        let mut a = b"attest-state/1\0".to_vec();
        a.extend_from_slice(sid.as_bytes());
        a.push(0);
        a.extend_from_slice(name.as_bytes());
        a
    }

    /// nonce || ciphertext of padded LZ4(plain), as for uploaded files.
    pub fn seal(&self, sid: &str, name: &str, plain: &[u8]) -> Result<Vec<u8>> {
        ensure!(plain.len() <= MAX_FILE_BYTES, "state record too large");
        let packed = pad_blob(lz4_flex::compress_prepend_size(plain));
        let mut nonce = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        let ct = self
            .seal
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: &packed, aad: &Self::aad(sid, name) })
            .map_err(|_| anyhow!("encryption failed"))?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn open(&self, sid: &str, name: &str, sealed: &[u8]) -> Result<Vec<u8>> {
        ensure!(sealed.len() >= 28, "state record {name} is too short");
        let plain = self
            .seal
            .decrypt(
                Nonce::from_slice(&sealed[..12]),
                Payload { msg: &sealed[12..], aad: &Self::aad(sid, name) },
            )
            .map_err(|_| anyhow!("state record {name} failed authentication"))?;
        let plain = unpad_blob(&plain).ok_or_else(|| anyhow!("state record {name} is malformed"))?;
        ensure!(plain.len() >= 4, "state record {name} is malformed");
        let declared = u32::from_le_bytes(plain[..4].try_into().unwrap()) as usize;
        ensure!(declared <= MAX_FILE_BYTES, "state record {name} is too large");
        lz4_flex::decompress_size_prepended(plain).map_err(|_| anyhow!("state record {name} is malformed"))
    }
}

/// Records above this are split into parts.
const PART_BYTES: usize = 32 << 20;

pub struct Persist {
    pub keys: Keys,
    pub blobs: BlobClient,
}

impl Persist {
    /// Seal and store one record; returns the sha256 of what was stored.
    pub async fn put(&self, sid: &str, name: &str, plain: &[u8]) -> Result<String> {
        let sealed = self.keys.seal(sid, name, plain)?;
        let hash = attest_core::sha256_hex(&sealed);
        self.blobs
            .put(&self.keys.id(sid, name), &sealed)
            .await
            .with_context(|| format!("storing state record {name}"))?;
        Ok(hash)
    }

    /// Fetch one record and check it is the one with `hash`.
    pub async fn get(&self, sid: &str, name: &str, hash: &str) -> Result<Vec<u8>> {
        let sealed = self
            .blobs
            .get(&self.keys.id(sid, name))
            .await?
            .with_context(|| format!("the parent lost state record {name}"))?;
        ensure!(
            attest_core::sha256_hex(&sealed) == hash,
            "state record {name} is not the expected version (stale or replaced by the parent)"
        );
        self.keys.open(sid, name, &sealed)
    }

    /// A record of any size, as parts `prefix/0`, `prefix/1`, ...
    pub async fn put_large(&self, sid: &str, prefix: &str, plain: &[u8]) -> Result<Vec<String>> {
        let mut hashes = Vec::new();
        for (i, part) in plain.chunks(PART_BYTES).enumerate() {
            hashes.push(self.put(sid, &format!("{prefix}/{i}"), part).await?);
        }
        if hashes.is_empty() {
            hashes.push(self.put(sid, &format!("{prefix}/0"), &[]).await?);
        }
        Ok(hashes)
    }

    pub async fn get_large(&self, sid: &str, prefix: &str, hashes: &[String]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for (i, h) in hashes.iter().enumerate() {
            out.extend(self.get(sid, &format!("{prefix}/{i}"), h).await?);
        }
        Ok(out)
    }

    /// Drop every record of a session (best effort, retried a few times).
    pub fn delete_session(&self, sid: &str) {
        let (blobs, tag) = (self.blobs.clone(), self.keys.tag(sid));
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                for attempt in 0..4u32 {
                    if blobs.delete_session(&tag).await.is_ok() {
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(15 << attempt)).await;
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_are_bound_to_their_names() {
        let k = Keys::generate();
        let s = k.seal("sid", "head", b"hello").unwrap();
        assert_eq!(k.open("sid", "head", &s).unwrap(), b"hello");
        assert!(k.open("sid", "other", &s).is_err());
        assert!(k.open("other", "head", &s).is_err());
        assert!(Keys::generate().open("sid", "head", &s).is_err());
        assert_eq!(k.id("sid", "a")[..8], k.id("sid", "b")[..8]);
        assert_ne!(k.id("sid", "a"), k.id("sid", "b"));
        assert_ne!(k.tag("sid"), k.tag("sid2"));
        assert_eq!(Keys::new(k.master()).id("sid", "a"), k.id("sid", "a"));
    }

    #[tokio::test]
    async fn large_records_and_freshness() {
        let p = Persist { keys: Keys::generate(), blobs: BlobClient::memory() };
        let big = vec![7u8; 100];
        let hashes = p.put_large("s", "snap/0", &big).await.unwrap();
        assert_eq!(p.get_large("s", "snap/0", &hashes).await.unwrap(), big);
        let old = p.put("s", "head", b"v1").await.unwrap();
        let new = p.put("s", "head", b"v2").await.unwrap();
        assert!(p.get("s", "head", &old).await.is_err());
        assert_eq!(p.get("s", "head", &new).await.unwrap(), b"v2");
    }
}
