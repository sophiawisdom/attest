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
//!
//! Before its first request, each enclave boot sends OP_RESET: everything
//! stored earlier is sealed under keys that died with the previous boot.
//! The parent deletes stored blobs only then, never on its own restart, so
//! restarting the parent's daemon doesn't lose live sessions' files.

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
pub const OP_RESET: u8 = 4;
/// Drop the parent's local cache (it may hold records another enclave has
/// since overwritten in the shared store).
pub const OP_DROP_CACHE: u8 = 5;
/// Largest single blob we store (plaintext). Bigger files are stored as
/// several parts of at most PART_BYTES (Sealer::seal_part).
pub const MAX_FILE_BYTES: usize = 64 << 20;
/// Plaintext bytes per part of a file stored in parts.
pub const PART_BYTES: usize = 32 << 20;
/// The parent's limit on one stored blob (crates/host: MAX_BLOB_BYTES).
pub const HOST_MAX_BLOB_BYTES: usize = 80 << 20;

/// Size of the largest sealed blob: an incompressible MAX_FILE_BYTES file
/// after LZ4 (with its size prefix), padding (with its length prefix) and
/// the nonce and tag.
pub fn max_sealed_len() -> usize {
    // LZ4's worst case for n bytes is n + n/255 + 16.
    let lz4_bound = MAX_FILE_BYTES + MAX_FILE_BYTES / 255 + 16;
    12 + 16 + bucket_for(lz4_bound + 4 + 4)
}

fn bucket_for(need: usize) -> usize {
    let mut bucket = 1024usize;
    while bucket < need {
        bucket += bucket / 4;
    }
    bucket
}

/// 8-byte session tag + 16-byte file id.
pub type BlobId = [u8; 24];

#[derive(Clone)]
pub struct BlobClient {
    dev: bool,
    dev_addr: String,
    /// Tests only: keep blobs in this process.
    memory: Option<Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>>,
    /// Set once this boot's OP_RESET (namespace selection) has reached the
    /// parent.
    reset: Arc<tokio::sync::OnceCell<()>>,
    /// The lineage id: the parent keeps each lineage's records apart, so a
    /// new lineage never touches the records another enclave may still
    /// hold the key to.
    lineage: Arc<std::sync::OnceLock<String>>,
    /// Set after this enclave handed its state to a successor: from then on
    /// only the successor writes, so puts and deletes are refused.
    fenced: Arc<std::sync::atomic::AtomicBool>,
}

impl BlobClient {
    pub fn new(dev: bool, dev_addr: String) -> Self {
        Self {
            dev,
            dev_addr,
            memory: None,
            reset: Arc::default(),
            lineage: Arc::default(),
            fenced: Arc::default(),
        }
    }

    /// Which lineage's records this enclave reads and writes. Set before
    /// any other call.
    pub fn set_lineage(&self, id: &str) {
        let _ = self.lineage.set(id.to_string());
    }

    /// Stop writing: a successor enclave owns the stored state now.
    pub fn fence(&self) {
        self.fenced.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn check_not_fenced(&self) -> Result<()> {
        ensure!(
            !self.fenced.load(std::sync::atomic::Ordering::SeqCst),
            "this enclave handed its state to a successor; it no longer writes"
        );
        Ok(())
    }

    #[cfg(test)]
    pub fn memory() -> Self {
        Self {
            dev: true,
            dev_addr: String::new(),
            memory: Some(Arc::default()),
            reset: Arc::default(),
            lineage: Arc::default(),
            fenced: Arc::default(),
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
                OP_DROP_CACHE => Some(vec![]),
                _ => {
                    m.retain(|k, _| !k.starts_with(id));
                    Some(vec![])
                }
            });
        }
        if op != OP_RESET {
            self.reset
                .get_or_try_init(|| async {
                    let lineage = self.lineage.get().ok_or_else(|| anyhow!("no lineage set for the blob store"))?;
                    self.call_raw(OP_RESET, &[], lineage.as_bytes()).await.map(|_| ())
                })
                .await
                .context("telling the blob store about this boot")?;
        }
        self.call_raw(op, id, data).await
    }

    async fn call_raw(&self, op: u8, id: &[u8], data: &[u8]) -> Result<Option<Vec<u8>>> {
        // Bounded, so the parent can't make many replies' buffers exist at
        // once.
        static SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(64);
        let _slot = SLOTS.acquire().await.map_err(|_| anyhow!("blob store closed"))?;
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
            // Only a successful get carries a blob; anything else is short.
            let cap = if status == 0 && op == OP_GET { max_sealed_len() } else { 4096 };
            ensure!(len <= cap, "blob store reply too large");
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
        ensure!(data.len() <= HOST_MAX_BLOB_BYTES, "sealed file too large for the blob store");
        self.check_not_fenced()?;
        self.call(OP_PUT, id, data).await.map(|_| ())
    }

    pub async fn get(&self, id: &BlobId) -> Result<Option<Vec<u8>>> {
        self.call(OP_GET, id, &[]).await
    }

    pub async fn drop_cache(&self) -> Result<()> {
        self.call(OP_DROP_CACHE, &[], &[]).await.map(|_| ())
    }

    /// Delete everything stored under `tag`, after a delay (a standby that
    /// hasn't seen the change yet may still need it: replica.rs), retrying
    /// for a while if the parent's store is unreachable. Bounded: past
    /// MAX_PENDING_DELETES the records are left in the store instead.
    pub fn delete_later(&self, tag: [u8; 8]) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static PENDING: AtomicUsize = AtomicUsize::new(0);
        const MAX_PENDING_DELETES: usize = 4096;
        const DELETE_AFTER: Duration = Duration::from_secs(600);
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            return;
        };
        if PENDING.fetch_add(1, Ordering::SeqCst) >= MAX_PENDING_DELETES {
            PENDING.fetch_sub(1, Ordering::SeqCst);
            return;
        }
        struct Done;
        impl Drop for Done {
            fn drop(&mut self) {
                PENDING.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let store = self.clone();
        rt.spawn(async move {
            let _done = Done;
            if store.memory.is_none() {
                tokio::time::sleep(DELETE_AFTER).await;
            }
            for attempt in 0..6u32 {
                if store.delete_session(&tag).await.is_ok() {
                    return;
                }
                tokio::time::sleep(Duration::from_secs(15 << attempt)).await;
            }
            crate::log("couldn't delete discarded records from the parent's store");
        });
    }

    pub async fn delete_session(&self, tag: &[u8; 8]) -> Result<()> {
        self.check_not_fenced()?;
        self.call(OP_DELETE_PREFIX, tag, &[]).await.map(|_| ())
    }
}

/// Per-upload sealing key and tag.
pub struct Sealer {
    pub tag: [u8; 8],
    key: [u8; 32],
    cipher: ChaCha20Poly1305,
    session_id: String,
}

impl Sealer {
    pub fn new(session_id: &str) -> Self {
        let mut key = [0u8; 32];
        let mut tag = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut tag);
        Self::from_parts(session_id, key, tag)
    }

    /// A sealer restored from durable state (see persist.rs).
    pub fn from_parts(session_id: &str, key: [u8; 32], tag: [u8; 8]) -> Self {
        Self {
            tag,
            key,
            cipher: ChaCha20Poly1305::new(Key::from_slice(&key)),
            session_id: session_id.to_string(),
        }
    }

    /// The key, for the sealed state record only.
    pub fn key(&self) -> [u8; 32] {
        self.key
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

    /// Returns (blob id, sealed bytes = nonce || ciphertext of padded
    /// LZ4(plain)). Compressing first means less to move over vsock and
    /// store; padding to a size bucket (1 KiB and up, 1.25x apart) means the
    /// host sees roughly how big a file is, not its exact compressed size,
    /// which could be matched against guesses of the content.
    pub fn seal(&self, path: &str, digest: &[u8; 32], plain: &[u8]) -> Result<(BlobId, Vec<u8>)> {
        let id = self.new_id();
        Ok((id, self.seal_with(&self.aad(path, digest), plain)?))
    }

    /// A fresh blob id in this sealer's namespace.
    pub fn new_id(&self) -> BlobId {
        let mut id = [0u8; 24];
        id[..8].copy_from_slice(&self.tag);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id[8..]);
        id
    }

    /// Part `index` of `count` of a file too big for one blob. A file's
    /// parts are bound to it by `first` (the id of its part 0, which is
    /// random), so the host can't swap, reorder or drop parts; the reader
    /// checks the whole file's digest once it has all of them.
    fn part_aad(&self, path: &str, first: &BlobId, index: u32, count: u32) -> Vec<u8> {
        let mut a = Vec::with_capacity(96 + path.len());
        a.extend_from_slice(b"attest-blob-part-v1\0");
        a.extend_from_slice(self.session_id.as_bytes());
        a.push(0);
        a.extend_from_slice(path.as_bytes());
        a.push(0);
        a.extend_from_slice(first);
        a.extend_from_slice(&index.to_le_bytes());
        a.extend_from_slice(&count.to_le_bytes());
        a
    }

    /// Seal one part (store it under a fresh id; part 0 under `first`).
    pub fn seal_part(&self, path: &str, first: &BlobId, index: u32, count: u32, plain: &[u8]) -> Result<Vec<u8>> {
        ensure!(plain.len() <= PART_BYTES, "a part of {path} is too large");
        self.seal_with(&self.part_aad(path, first, index, count), plain)
    }

    /// Open one part (its content is checked with the whole file's digest).
    pub fn open_part(&self, path: &str, first: &BlobId, index: u32, count: u32, sealed: &[u8]) -> Result<Vec<u8>> {
        self.open_with(path, &self.part_aad(path, first, index, count), sealed)
    }

    fn seal_with(&self, aad: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
        let packed = pad_blob(lz4_flex::compress_prepend_size(plain));
        let mut nonce = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        let ct = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: &packed[..], aad })
            .map_err(|_| anyhow!("encryption failed"))?;
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn open(&self, path: &str, digest: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>> {
        let plain = self.open_with(path, &self.aad(path, digest), sealed)?;
        ensure!(
            &attest_core::sha256(&plain) == digest,
            "stored copy of {path} has the wrong content"
        );
        Ok(plain)
    }

    fn open_with(&self, path: &str, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
        ensure!(sealed.len() >= 12 + 16, "sealed file too short");
        let plain = self
            .cipher
            .decrypt(Nonce::from_slice(&sealed[..12]), Payload { msg: &sealed[12..], aad })
            .map_err(|_| {
                anyhow!(
                    "stored copy of {path} failed authentication (tampered or swapped by the host)"
                )
            })?;
        let plain = unpad_blob(&plain).ok_or_else(|| anyhow!("stored copy of {path} is malformed"))?;
        ensure!(plain.len() >= 4, "stored copy of {path} is malformed");
        let declared = u32::from_le_bytes(plain[..4].try_into().unwrap()) as usize;
        ensure!(
            declared <= MAX_FILE_BYTES,
            "stored copy of {path} is too large"
        );
        lz4_flex::decompress_size_prepended(plain).map_err(|_| anyhow!("stored copy of {path} is malformed"))
    }
}

/// `len || data || zeros`, up to the next size bucket.
pub(crate) fn pad_blob(data: Vec<u8>) -> Vec<u8> {
    let bucket = bucket_for(data.len() + 4);
    let mut out = Vec::with_capacity(bucket);
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&data);
    out.resize(bucket, 0);
    out
}

pub(crate) fn unpad_blob(b: &[u8]) -> Option<&[u8]> {
    let n = u32::from_le_bytes(b.get(..4)?.try_into().ok()?) as usize;
    b.get(4..4 + n)
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
    fn largest_blob_fits_both_ends() {
        let n = max_sealed_len();
        assert!(n <= HOST_MAX_BLOB_BYTES, "{n}");
        let s = Sealer::new("s");
        let big: Vec<u8> = (0..MAX_FILE_BYTES as u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        let sealed = s.seal("big", &attest_core::sha256(&big), &big).unwrap().1;
        assert!(sealed.len() <= n, "{} > {n}", sealed.len());
    }

    #[test]
    fn padding_hides_exact_size() {
        let s = Sealer::new("s");
        let d = |b: &[u8]| attest_core::sha256(b);
        let a = s.seal("a", &d(b"x"), b"x").unwrap().1.len();
        let b = s.seal("b", &d(&[7u8; 300]), &[7u8; 300]).unwrap().1.len();
        assert_eq!(a, b, "small files land in the same bucket");
        let big: Vec<u8> = (0..100_000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
        let sealed = s.seal("c", &d(&big), &big).unwrap().1;
        assert_eq!(s.open("c", &d(&big), &sealed).unwrap(), big);
    }

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
