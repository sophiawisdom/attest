//! A standby: a second enclave of the same image that holds the lineage's
//! keys and follows the primary's writes, so the sessions survive the
//! primary's machine dying.
//!
//! The standby gets its copy with the handoff exchange (handoff.rs, `copy`),
//! which leaves the primary serving and gives both sides a shared channel
//! key. From then on the standby long-polls the primary for the hash of
//! each session's latest head record, so if it takes over it reads exactly
//! the state the primary last wrote, and the parent can't feed it older
//! records. Each poll also confirms what the standby has, and the primary
//! holds back its answer to a request that changed a session until the
//! standby has that change (or a few seconds pass).
//!
//! The standby serves no sessions until the operator promotes it, which it
//! accepts only after it has lost contact with the primary for a while. If
//! the operator cuts the two apart while both are up, both may serve: a
//! party would then see one of them only, which can hide recent changes
//! from them but not invent any (everything stays signed by the lineage).

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
use tokio::sync::watch;

const SYNC: &[u8] = b"attest-replica-sync/1";
const SYNC_RESPONSE: &[u8] = b"attest-replica-sync-response/1";
const PROMOTE: &[u8] = b"attest-replica-promote/1";

/// How long a sync waits for something new before answering anyway.
const POLL: Duration = Duration::from_secs(20);
/// A standby not heard from for this long no longer holds requests back.
const LIVE: Duration = Duration::from_secs(45);
/// How long a request waits for the standby to confirm its change.
const CONFIRM: Duration = Duration::from_secs(10);
/// A standby accepts promotion only after this long without contact.
pub const FAILOVER_SILENCE: Duration = Duration::from_secs(20);
const MAX_STANDBYS: usize = 2;

fn sync_mac(key: &[u8; 32], id: &[u8], n: u64, after: u64) -> Vec<u8> {
    let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    ring::hmac::sign(&k, &hash(&[SYNC, id, &n.to_le_bytes(), &after.to_le_bytes()])).as_ref().to_vec()
}

fn response_nonce(id: &[u8], n: u64) -> [u8; 12] {
    hash(&[SYNC_RESPONSE, id, &n.to_le_bytes()])[..12].try_into().unwrap()
}

struct Standby {
    id: [u8; 32],
    n_r: [u8; 32],
    key: [u8; 32],
    /// The copy's response, sent again if the standby asks again.
    resp: Value,
    last_n: u64,
    acked: u64,
    seen: Instant,
}

struct State {
    seq: u64,
    digest: [u8; 32],
    heads: Vec<(String, String)>,
    standbys: Vec<Standby>,
}

/// The primary's side.
pub struct Replication {
    st: Mutex<State>,
    seq: watch::Sender<u64>,
    acked: watch::Sender<u64>,
    warned: AtomicU64,
}

impl Default for Replication {
    fn default() -> Self {
        Self {
            st: Mutex::new(State { seq: 0, digest: [0; 32], heads: Vec::new(), standbys: Vec::new() }),
            seq: watch::channel(0).0,
            acked: watch::channel(0).0,
            warned: AtomicU64::new(0),
        }
    }
}

impl Replication {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The response for a standby asking again for the copy it got.
    pub fn repeat(&self, id: &[u8; 32], n_r: &[u8; 32]) -> Option<Value> {
        self.lock().standbys.iter().find(|s| &s.id == id && &s.n_r == n_r).map(|s| s.resp.clone())
    }

    pub fn add(&self, id: [u8; 32], n_r: [u8; 32], key: [u8; 32], resp: Value) {
        let mut st = self.lock();
        if st.standbys.len() >= MAX_STANDBYS {
            // Replace the one heard from least recently.
            if let Some(i) = (0..st.standbys.len()).min_by_key(|&i| st.standbys[i].seen) {
                st.standbys.remove(i);
            }
        }
        st.standbys.push(Standby { id, n_r, key, resp, last_n: 0, acked: 0, seen: Instant::now() });
    }

    /// Record the sessions' current heads (after a write).
    pub fn publish(&self, mut heads: Vec<(String, String)>) {
        heads.sort();
        let flat: Vec<u8> = heads.iter().flat_map(|(s, h)| [s.as_bytes(), b"=", h.as_bytes(), b"\n"].concat()).collect();
        let digest = hash(&[&flat]);
        let mut st = self.lock();
        if digest != st.digest || st.seq == 0 {
            st.seq += 1;
            st.digest = digest;
            st.heads = heads;
            self.seq.send_replace(st.seq);
        }
    }

    fn live(&self) -> bool {
        self.lock().standbys.iter().any(|s| s.seen.elapsed() < LIVE)
    }

    /// A standby's poll: confirms what it has, then waits for something
    /// newer and answers with it, encrypted to the channel key.
    pub async fn sync(&self, body: &Value) -> Result<Value> {
        let id: [u8; 32] = hex::decode(body["id"].as_str().context("id")?)?
            .try_into()
            .map_err(|_| anyhow!("bad id"))?;
        let n = body["n"].as_u64().context("n")?;
        let after = body["after"].as_u64().context("after")?;
        let key = {
            let mut st = self.lock();
            let seq = st.seq;
            let s = st.standbys.iter_mut().find(|s| s.id == id).context("unknown standby")?;
            let want_msg = hash(&[SYNC, &id, &n.to_le_bytes(), &after.to_le_bytes()]);
            let got = hex::decode(body["mac"].as_str().unwrap_or("")).unwrap_or_default();
            let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &s.key);
            ensure!(ring::hmac::verify(&k, &want_msg, &got).is_ok(), "bad mac");
            ensure!(n > s.last_n, "replayed sync");
            s.last_n = n;
            s.acked = after.min(seq);
            s.seen = Instant::now();
            s.key
        };
        let best = self.lock().standbys.iter().map(|s| s.acked).max().unwrap_or(0);
        self.acked.send_replace(best);
        let mut rx = self.seq.subscribe();
        let _ = tokio::time::timeout(POLL, rx.wait_for(|s| *s > after)).await;
        let plain = {
            let st = self.lock();
            serde_json::to_vec(&json!({"seq": st.seq, "heads": st.heads}))?
        };
        let mut aad = SYNC_RESPONSE.to_vec();
        aad.extend_from_slice(&id);
        aad.extend_from_slice(&n.to_le_bytes());
        let ct = ChaCha20Poly1305::new(Key::from_slice(&key))
            .encrypt(Nonce::from_slice(&response_nonce(&id, n)), Payload { msg: &plain, aad: &aad })
            .map_err(|_| anyhow!("encryption failed"))?;
        Ok(json!({"ciphertext": b64().encode(ct)}))
    }

    /// After a request changed a session: write it now and wait until a live
    /// standby has it. Without a live standby this returns at once.
    pub async fn confirm(&self, ctx: &Arc<Ctx>) {
        if !self.live() || ctx.standby.load(Ordering::SeqCst) {
            return;
        }
        // The write runs on its own task, so a request that goes away
        // doesn't cut it short; the whole wait is bounded.
        let c = ctx.clone();
        let write = tokio::spawn(async move {
            c.store.write_changed(&c.persist).await;
            c.repl.publish(c.store.heads_now());
        });
        let wait = async {
            let _ = write.await;
            let target = *self.seq.borrow();
            let mut rx = self.acked.subscribe();
            let _ = rx.wait_for(|a| *a >= target).await;
        };
        if tokio::time::timeout(CONFIRM, wait).await.is_err() {
            let now = attest_core::now_ms();
            if now.saturating_sub(self.warned.swap(now, Ordering::Relaxed)) > 60_000 {
                crate::log("replica: the standby didn't confirm a change in time; answering anyway");
            }
        }
    }
}

/// The standby's side.
pub struct Follower {
    peer: String,
    dev: bool,
    id: [u8; 32],
    key: [u8; 32],
    n: AtomicU64,
    latest: Mutex<(u64, Vec<(String, String)>)>,
    contact: Mutex<Instant>,
    promoted: AtomicBool,
    promoting: tokio::sync::Mutex<()>,
}

impl Follower {
    pub fn new(peer: &str, dev: bool, id: [u8; 32], key: [u8; 32], heads: Vec<(String, String)>) -> Self {
        Self {
            peer: peer.to_string(),
            dev,
            id,
            key,
            n: AtomicU64::new(0),
            latest: Mutex::new((0, heads)),
            contact: Mutex::new(Instant::now()),
            promoted: AtomicBool::new(false),
            promoting: tokio::sync::Mutex::new(()),
        }
    }

    pub fn silence(&self) -> Duration {
        self.contact.lock().unwrap_or_else(|e| e.into_inner()).elapsed()
    }

    /// Poll the primary until promoted.
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
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }

    async fn sync_once(&self, net: &Net) -> Result<()> {
        let n = self.n.fetch_add(1, Ordering::SeqCst) + 1;
        let after = self.latest.lock().unwrap_or_else(|e| e.into_inner()).0;
        let body = json!({
            "id": hex::encode(self.id),
            "n": n,
            "after": after,
            "mac": hex::encode(sync_mac(&self.key, &self.id, n, after)),
        });
        let (host, port) = split_peer(&self.peer)?;
        let resp = net
            .request_peer("POST", !self.dev, &host, port, "/api/internal/replica/sync", serde_json::to_vec(&body)?, POLL + Duration::from_secs(20))
            .await?;
        let v: Value = serde_json::from_slice(&resp.body).unwrap_or(Value::Null);
        ensure!(resp.status == 200, "HTTP {}: {}", resp.status, v["error"].as_str().unwrap_or(""));
        let ct = b64().decode(v["ciphertext"].as_str().context("no ciphertext")?)?;
        let mut aad = SYNC_RESPONSE.to_vec();
        aad.extend_from_slice(&self.id);
        aad.extend_from_slice(&n.to_le_bytes());
        let plain = ChaCha20Poly1305::new(Key::from_slice(&self.key))
            .decrypt(Nonce::from_slice(&response_nonce(&self.id, n)), Payload { msg: &ct, aad: &aad })
            .map_err(|_| anyhow!("a sync response failed authentication"))?;
        let v: Value = serde_json::from_slice(&plain)?;
        let seq = v["seq"].as_u64().context("seq")?;
        let heads: Vec<(String, String)> = serde_json::from_value(v["heads"].clone())?;
        let mut l = self.latest.lock().unwrap_or_else(|e| e.into_inner());
        // Never go back: an older answer (a delayed response) is ignored.
        if seq >= l.0 {
            *l = (seq, heads);
        }
        Ok(())
    }

    /// Become the primary: only for the operator, and only once the old
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
        // Nothing changes until the cache is cleared; on failure the standby
        // just keeps following.
        ctx.blobs
            .drop_cache()
            .await
            .context("clearing the parent's cache before reading state")?;
        self.promoted.store(true, Ordering::SeqCst);
        let (seq, heads) = self.latest.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let total = heads.len();
        let restored = ctx.store.restore(ctx, heads).await;
        ctx.standby.store(false, Ordering::SeqCst);
        tokio::spawn(crate::sessions::write_loop(ctx.clone()));
        crate::log(&format!(
            "replica: promoted after {}s without the primary; restored {restored} of {total} sessions (state #{seq})",
            silence.as_secs()
        ));
        Ok(json!({"promoted": true, "sessions": total, "restored": restored}))
    }
}
