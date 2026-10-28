//! Encrypted file storage on the untrusted parent.
//!
//! Each uploaded file is sealed with ChaCha20-Poly1305 under a per-session
//! key that never leaves the enclave, and handed to the parent under a
//! random id. The associated data binds the ciphertext to its session, path
//! and content hash, so the parent cannot read, alter, swap or roll back a
//! file; it learns only how many files there are, their sizes, and when each
//! is fetched. The key dies with the enclave, so leftovers are noise.
//!
//! Wire protocol (one request per connection):
//!   request:  op u8 | id [24] | len u64le | data
//!   response: status u8 (0 ok, 1 not found, 2 error) | len u64le | data

use anyhow::{anyhow, bail, ensure, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub const BLOB_VSOCK_PORT: u32 = 5005;
pub const OP_PUT: u8 = 1;
pub const OP_GET: u8 = 2;
pub const OP_DELETE_PREFIX: u8 = 3;
/// Largest single file we store (plaintext).
pub const MAX_FILE_BYTES: usize = 64 << 20;

/// 8-byte session tag + 16-byte file id.
pub type BlobId = [u8; 24];

#[derive(Clone)]
pub struct BlobClient {
    dev: bool,
    dev_addr: String,
    /// Tests only: keep blobs in this process.
    memory: Option<Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>>,
}

impl BlobClient {
    pub fn new(dev: bool, dev_addr: String) -> Self {
        Self {
            dev,
            dev_addr,
            memory: None,
        }
    }

    #[cfg(test)]
    pub fn memory() -> Self {
        Self {
            dev: true,
            dev_addr: String::new(),
            memory: Some(Arc::default()),
        }
    }

    async fn connect(&self) -> Result<Box<dyn crate::net::Io>> {
        if self.dev {
            return Ok(Box::new(
                tokio::net::TcpStream::connect(&self.dev_addr)
                    .await
                    .with_context(|| format!("dev blob store at {}", self.dev_addr))?,
            ));
        }
        #[cfg(target_os = "linux")]
        {
            Ok(Box::new(
                crate::net::vsock_connect(BLOB_VSOCK_PORT)
                    .await
                    .context("parent blob store")?,
            ))
        }
        #[cfg(not(target_os = "linux"))]
        bail!("vsock requires linux")
    }

    async fn call(&self, op: u8, id: &[u8], data: &[u8]) -> Result<Option<Vec<u8>>> {
        if let Some(m) = &self.memory {
            let mut m = m.lock().unwrap();
            return Ok(match op {
                OP_PUT => {
                    m.insert(id.to_vec(), data.to_vec());
                    Some(vec![])
                }
                OP_GET => m.get(id).cloned(),
                _ => {
                    m.retain(|k, _| !k.starts_with(id));
                    Some(vec![])
                }
            });
        }
        let fut = async {
            let mut s = self.connect().await?;
            let mut head = Vec::with_capacity(33);
            head.push(op);
            let mut idb = [0u8; 24];
            idb[..id.len()].copy_from_slice(id);
            head.extend_from_slice(&idb);
            head.extend_from_slice(&(data.len() as u64).to_le_bytes());
            s.write_all(&head).await?;
            s.write_all(data).await?;
            s.flush().await?;
            let status = s.read_u8().await?;
            let len = s.read_u64_le().await? as usize;
            ensure!(len <= MAX_FILE_BYTES + 1024, "blob store reply too large");
            let mut buf = vec![0u8; len];
            s.read_exact(&mut buf).await?;
            match status {
                0 => Ok(Some(buf)),
                1 => Ok(None),
                _ => bail!("blob store error: {}", String::from_utf8_lossy(&buf)),
            }
        };
        tokio::time::timeout(Duration::from_secs(120), fut)
            .await
            .map_err(|_| anyhow!("blob store timed out"))?
    }

    pub async fn put(&self, id: &BlobId, data: &[u8]) -> Result<()> {
        self.call(OP_PUT, id, data).await.map(|_| ())
    }

    pub async fn get(&self, id: &BlobId) -> Result<Option<Vec<u8>>> {
        self.call(OP_GET, id, &[]).await
    }

    pub async fn delete_session(&self, tag: &[u8; 8]) -> Result<()> {
        self.call(OP_DELETE_PREFIX, tag, &[]).await.map(|_| ())
    }
}

/// Per-session sealing key and tag.
pub struct Sealer {
    pub tag: [u8; 8],
    cipher: ChaCha20Poly1305,
    session_id: String,
}

impl Sealer {
    pub fn new(session_id: &str) -> Self {
        let mut key = [0u8; 32];
        let mut tag = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut tag);
        Self {
            tag,
            cipher: ChaCha20Poly1305::new(Key::from_slice(&key)),
            session_id: session_id.to_string(),
        }
    }

    fn aad(&self, path: &str, digest: &[u8; 32]) -> Vec<u8> {
        let mut a = Vec::with_capacity(64 + path.len());
        a.extend_from_slice(b"attest-blob-v2\0");
        a.extend_from_slice(self.session_id.as_bytes());
        a.push(0);
        a.extend_from_slice(path.as_bytes());
        a.push(0);
        a.extend_from_slice(digest);
        a
    }

    /// Returns (blob id, sealed bytes = nonce || ciphertext of LZ4(plain)).
    /// Compressing first means less to move over vsock and store.
    pub fn seal(&self, path: &str, digest: &[u8; 32], plain: &[u8]) -> Result<(BlobId, Vec<u8>)> {
        let packed = lz4_flex::compress_prepend_size(plain);
        let plain = &packed[..];
        let mut id = [0u8; 24];
        id[..8].copy_from_slice(&self.tag);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id[8..]);
        let mut nonce = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        let ct = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plain,
                    aad: &self.aad(path, digest),
                },
            )
            .map_err(|_| anyhow!("encryption failed"))?;
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok((id, out))
    }

    pub fn open(&self, path: &str, digest: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>> {
        ensure!(sealed.len() >= 12 + 16, "sealed file too short");
        let plain = self
            .cipher
            .decrypt(
                Nonce::from_slice(&sealed[..12]),
                Payload {
                    msg: &sealed[12..],
                    aad: &self.aad(path, digest),
                },
            )
            .map_err(|_| {
                anyhow!(
                    "stored copy of {path} failed authentication (tampered or swapped by the host)"
                )
            })?;
        ensure!(plain.len() >= 4, "stored copy of {path} is malformed");
        let declared = u32::from_le_bytes(plain[..4].try_into().unwrap()) as usize;
        ensure!(
            declared <= MAX_FILE_BYTES,
            "stored copy of {path} is too large"
        );
        let plain = lz4_flex::decompress_size_prepended(&plain)
            .map_err(|_| anyhow!("stored copy of {path} is malformed"))?;
        ensure!(
            &attest_core::sha256(&plain) == digest,
            "stored copy of {path} has the wrong content"
        );
        Ok(plain)
    }
}

/// Decrypted-file cache shared by all sessions, bounded in bytes.
pub struct Cache {
    budget: usize,
    inner: Mutex<(HashMap<BlobId, Arc<Vec<u8>>>, VecDeque<BlobId>, usize)>,
}

impl Cache {
    pub fn new(budget: usize) -> Self {
        Self {
            budget,
            inner: Mutex::new((HashMap::new(), VecDeque::new(), 0)),
        }
    }

    pub fn get(&self, id: &BlobId) -> Option<Arc<Vec<u8>>> {
        let mut g = self.inner.lock().unwrap();
        let hit = g.0.get(id).cloned();
        if hit.is_some() {
            if let Some(pos) = g.1.iter().position(|x| x == id) {
                g.1.remove(pos);
                g.1.push_back(*id);
            }
        }
        hit
    }

    pub fn put(&self, id: BlobId, data: Arc<Vec<u8>>) {
        if data.len() > self.budget / 4 {
            return;
        }
        let mut g = self.inner.lock().unwrap();
        g.2 += data.len();
        if let Some(old) = g.0.insert(id, data) {
            g.2 -= old.len();
        } else {
            g.1.push_back(id);
        }
        while g.2 > self.budget {
            let Some(victim) = g.1.pop_front() else { break };
            if let Some(v) = g.0.remove(&victim) {
                g.2 -= v.len();
            }
        }
    }

    pub fn forget_session(&self, tag: &[u8; 8]) {
        let mut g = self.inner.lock().unwrap();
        let ids: Vec<BlobId> = g.0.keys().filter(|k| &k[..8] == tag).copied().collect();
        for id in ids {
            if let Some(v) = g.0.remove(&id) {
                g.2 -= v.len();
            }
        }
        g.1.retain(|k| &k[..8] != tag);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_and_tamper() {
        let s = Sealer::new("sess");
        let d = attest_core::sha256(b"hello");
        let (_, sealed) = s.seal("a.txt", &d, b"hello").unwrap();
        assert_eq!(s.open("a.txt", &d, &sealed).unwrap(), b"hello");
        // Swapping the file under another path fails.
        assert!(s.open("b.txt", &d, &sealed).is_err());
        // Flipping a byte fails.
        let mut t = sealed.clone();
        let n = t.len() - 1;
        t[n] ^= 1;
        assert!(s.open("a.txt", &d, &t).is_err());
        // Another session's key can't open it.
        assert!(Sealer::new("sess").open("a.txt", &d, &sealed).is_err());
    }

    #[test]
    fn cache_respects_budget() {
        let c = Cache::new(100);
        let id = |n: u8| {
            let mut i = [0u8; 24];
            i[23] = n;
            i
        };
        for n in 0..10 {
            c.put(id(n), Arc::new(vec![0u8; 20]));
        }
        assert!(c.get(&id(0)).is_none());
        assert!(c.get(&id(9)).is_some());
    }
}
