//! A standby: a second enclave of the same image that holds the lineage's
//! keys, so the sessions survive the primary's machine dying.
//!
//! The standby gets the keys with the handoff exchange (handoff.rs, `copy`),
//! which leaves the primary serving and gives both sides a shared channel
//! key. It copies no session data: every session is already sealed in the
//! shared store. It only checks, every few seconds, that the primary is
//! alive (an authenticated heartbeat under the channel key).
//!
//! The standby serves no sessions until it is promoted, which it accepts
//! only after the primary has been silent for a while. It then reads the
//! lineage's session index and each session's latest head straight from
//! the store (sessions/durable.rs). The parent could serve older records
//! there, or cut two healthy enclaves apart so both serve: either way a
//! party may miss recent changes, but nothing can be invented (everything
//! stays sealed and signed by the lineage).

use crate::handoff::{b64, hash, mac_ok, split_peer};
use crate::net::Net;
use crate::sessions::Ctx;
use anyhow::{anyhow, ensure, Context, Result};
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const SYNC: &[u8] = b"attest-replica-sync/1";
const SYNC_RESPONSE: &[u8] = b"attest-replica-sync-response/1";
const PROMOTE: &[u8] = b"attest-replica-promote/1";

/// How often the standby checks on the primary.
const HEARTBEAT: Duration = Duration::from_secs(3);
/// A standby accepts promotion only after this long without contact.
pub const FAILOVER_SILENCE: Duration = Duration::from_secs(20);
const MAX_STANDBYS: usize = 2;

fn sync_mac(key: &[u8; 32], id: &[u8], n: u64) -> Vec<u8> {
    let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    ring::hmac::sign(&k, &hash(&[SYNC, id, &n.to_le_bytes()])).as_ref().to_vec()
}

fn response_nonce(id: &[u8], n: u64) -> [u8; 12] {
    hash(&[SYNC_RESPONSE, id, &n.to_le_bytes()])[..12].try_into().unwrap()
}

fn response_aad(id: &[u8], n: u64) -> Vec<u8> {
    [SYNC_RESPONSE, id, &n.to_le_bytes()].concat()
}

struct Standby {
    id: [u8; 32],
    n_r: [u8; 32],
    key: [u8; 32],
    /// The copy's response, sent again if the standby asks again.
    resp: Value,
    last_n: u64,
    seen: Instant,
}

/// The primary's side: the standbys that took a copy.
#[derive(Default)]
pub struct Replication {
    standbys: Mutex<Vec<Standby>>,
}

impl Replication {
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Standby>> {
        self.standbys.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The response for a standby asking again for the copy it got.
    pub fn repeat(&self, id: &[u8; 32], n_r: &[u8; 32]) -> Option<Value> {
        self.lock().iter().find(|s| &s.id == id && &s.n_r == n_r).map(|s| s.resp.clone())
    }

    pub fn add(&self, id: [u8; 32], n_r: [u8; 32], key: [u8; 32], resp: Value) {
        let mut st = self.lock();
        if st.len() >= MAX_STANDBYS {
            // Replace the one heard from least recently.
            if let Some(i) = (0..st.len()).min_by_key(|&i| st[i].seen) {
                st.remove(i);
            }
        }
        st.push(Standby { id, n_r, key, resp, last_n: 0, seen: Instant::now() });
    }

    /// A standby's heartbeat, answered encrypted to the channel key so the
    /// parent can't answer for this enclave.
    pub fn sync(&self, body: &Value, boot_id: &str) -> Result<Value> {
        let id: [u8; 32] = hex::decode(body["id"].as_str().context("id")?)?
            .try_into()
            .map_err(|_| anyhow!("bad id"))?;
        let n = body["n"].as_u64().context("n")?;
        let key = {
            let mut st = self.lock();
            let s = st.iter_mut().find(|s| s.id == id).context("unknown standby")?;
            let got = hex::decode(body["mac"].as_str().unwrap_or("")).unwrap_or_default();
            let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &s.key);
            ensure!(ring::hmac::verify(&k, &hash(&[SYNC, &id, &n.to_le_bytes()]), &got).is_ok(), "bad mac");
            ensure!(n > s.last_n, "replayed sync");
            s.last_n = n;
            s.seen = Instant::now();
            s.key
        };
        let plain = serde_json::to_vec(&json!({"alive": true, "boot_id": boot_id}))?;
        let ct = ChaCha20Poly1305::new(Key::from_slice(&key))
            .encrypt(Nonce::from_slice(&response_nonce(&id, n)), Payload { msg: &plain, aad: &response_aad(&id, n) })
            .map_err(|_| anyhow!("encryption failed"))?;
        Ok(json!({"ciphertext": b64().encode(ct)}))
    }
}

/// The standby's side.
pub struct Follower {
    peer: String,
    dev: bool,
    id: [u8; 32],
    key: [u8; 32],
    n: AtomicU64,
    contact: Mutex<Instant>,
    promoted: AtomicBool,
    promoting: tokio::sync::Mutex<()>,
}

impl Follower {
    pub fn new(peer: &str, dev: bool, id: [u8; 32], key: [u8; 32]) -> Self {
        Self {
            peer: peer.to_string(),
            dev,
            id,
            key,
            n: AtomicU64::new(0),
            contact: Mutex::new(Instant::now()),
            promoted: AtomicBool::new(false),
            promoting: tokio::sync::Mutex::new(()),
        }
    }

    pub fn silence(&self) -> Duration {
        self.contact.lock().unwrap_or_else(|e| e.into_inner()).elapsed()
    }

    /// Check on the primary until promoted.
    pub async fn follow(self: Arc<Self>, net: Net) {
        let mut failing_since: Option<Instant> = None;
        while !self.promoted.load(Ordering::SeqCst) {
            match self.sync_once(&net).await {
                Ok(()) => {
                    if failing_since.take().is_some() {
                        crate::log("replica: back in contact with the primary");
                    }
                    *self.contact.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
                }
                Err(e) => {
                    if failing_since.is_none() {
                        crate::log(&format!("replica: lost contact with the primary: {e:#}"));
                        failing_since = Some(Instant::now());
                    }
                }
            }
            tokio::time::sleep(HEARTBEAT).await;
        }
    }

    async fn sync_once(&self, net: &Net) -> Result<()> {
        let n = self.n.fetch_add(1, Ordering::SeqCst) + 1;
        let body = json!({"id": hex::encode(self.id), "n": n, "mac": hex::encode(sync_mac(&self.key, &self.id, n))});
        let (host, port) = split_peer(&self.peer)?;
        let resp = net
            .request_peer("POST", !self.dev, &host, port, "/api/internal/replica/sync", serde_json::to_vec(&body)?, Duration::from_secs(10))
            .await?;
        let v: Value = serde_json::from_slice(&resp.body).unwrap_or(Value::Null);
        ensure!(resp.status == 200, "HTTP {}: {}", resp.status, v["error"].as_str().unwrap_or(""));
        let ct = b64().decode(v["ciphertext"].as_str().context("no ciphertext")?)?;
        let plain = ChaCha20Poly1305::new(Key::from_slice(&self.key))
            .decrypt(Nonce::from_slice(&response_nonce(&self.id, n)), Payload { msg: &ct, aad: &response_aad(&self.id, n) })
            .map_err(|_| anyhow!("a heartbeat response failed authentication"))?;
        let v: Value = serde_json::from_slice(&plain)?;
        ensure!(v["alive"] == true, "malformed heartbeat");
        Ok(())
    }

    /// Become the primary: needs the operator's token, and only once the old
    /// primary has been out of contact for a while. Runs on its own task, so
    /// a dropped request can't leave it half done.
    pub async fn promote(self: &Arc<Self>, ctx: &Arc<Ctx>, token: Option<&str>, body: &Value) -> Result<Value> {
        let token = token.filter(|t| t.len() >= 16).context("promotion is not enabled on this enclave")?;
        ensure!(mac_ok(token, &[PROMOTE], &body["mac"]), "wrong handoff token");
        let (me, ctx) = (self.clone(), ctx.clone());
        tokio::spawn(async move { me.promote_inner(&ctx).await }).await.map_err(|e| anyhow!("promotion failed: {e}"))?
    }

    async fn promote_inner(&self, ctx: &Arc<Ctx>) -> Result<Value> {
        let _one = self.promoting.lock().await;
        ensure!(ctx.standby.load(Ordering::SeqCst), "this enclave is already serving");
        let silence = self.silence();
        ensure!(
            silence >= FAILOVER_SILENCE,
            "the primary answered {}s ago; promote only after it has been unreachable for {}s (or move it with a handoff)",
            silence.as_secs(),
            FAILOVER_SILENCE.as_secs()
        );
        // The parent's cache holds only what this machine read; the primary
        // wrote elsewhere since. Nothing changes until it's cleared.
        ctx.blobs
            .drop_cache()
            .await
            .context("clearing the parent's cache before reading state")?;
        let (total, restored) = ctx.store.restore_latest(ctx).await.context("reading the session index")?;
        self.promoted.store(true, Ordering::SeqCst);
        ctx.standby.store(false, Ordering::SeqCst);
        tokio::spawn(crate::sessions::write_loop(ctx.clone()));
        crate::log(&format!(
            "replica: promoted after {}s without the primary; restored {restored} of {total} sessions",
            silence.as_secs()
        ));
        Ok(json!({"promoted": true, "sessions": total, "restored": restored}))
    }
}
