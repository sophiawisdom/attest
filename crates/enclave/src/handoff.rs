//! Handing an enclave's sessions to a successor running the same image, on
//! a bigger machine or in another region.
//!
//! What moves is small: the lineage's master key (persist.rs), which opens
//! all stored state, the long-term signing key, and the hash of each
//! session's latest state record. It moves only between enclaves that each
//! prove, with a fresh Nitro attestation, the same PCR0-2 as themselves, so
//! neither the operator nor a different build can obtain it.
//!
//!   R (receiver, new)                         G (giver, running)
//!   GET  /api/internal/handoff/challenge  ->  nG (fresh, single use)
//!   attestation over (user_data = H(req | nR), public_key = R's one-time
//!   X25519 key, nonce = nG)
//!   POST /api/internal/handoff            ->  G checks it: genuine Nitro,
//!        {challenge, public_key, nonce: nR,       same PCR0-2 as G, nonce nG,
//!         document}                              key and nR bound in it.
//!                                             G stops serving sessions,
//!                                             writes all state, fences its
//!                                             store, and encrypts the
//!                                             payload to R's key (X25519 +
//!                                             ChaCha20-Poly1305).
//!                                         <-  {public_key: G's one-time key,
//!                                              ciphertext, document}: an
//!                                             attestation over (user_data =
//!                                             H(resp | nR | R key | G key |
//!                                             H(ciphertext)), nonce = nR)
//!   R checks G's attestation the same way, so the parent can't hand R a
//!   key or state of its own, then decrypts.
//!
//! The transport (TLS through the parents) carries no trust: both ends rely
//! on the attestations alone. A giver hands over once; after that it only
//! answers that its sessions moved, so there is one writer.

use crate::net::Net;
use crate::nsm::Attester;
use anyhow::{anyhow, ensure, Context, Result};
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload as AeadPayload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ring::agreement;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const REQUEST: &[u8] = b"attest-handoff-request/1";
const RESPONSE: &[u8] = b"attest-handoff-response/1";
const KEY: &[u8] = b"attest-handoff-key/1";

/// What the giver hands over, encrypted to the receiver.
#[derive(Serialize, Deserialize)]
pub struct Payload {
    pub master_key: String,
    pub signing_key: String,
    pub lineage_id: String,
    /// The giver's generation; the receiver's is one more.
    pub generation: u32,
    pub giver_boot: String,
    /// Every session and the hash of its latest head record.
    pub sessions: Vec<(String, String)>,
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Vec::new();
    for p in parts {
        h.extend_from_slice(&(p.len() as u64).to_le_bytes());
        h.extend_from_slice(p);
    }
    attest_core::sha256(&h)
}

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    b
}

fn hex32(v: &Value, what: &str) -> Result<[u8; 32]> {
    hex::decode(v.as_str().with_context(|| format!("{what} is required"))?)?
        .try_into()
        .map_err(|_| anyhow!("{what} must be 32 bytes"))
}

/// This enclave's own PCR0-2, from a fresh attestation. None in dev mode,
/// which has no attestation and so can only hand off to dev enclaves.
pub fn own_pcrs(att: &Attester) -> Result<Option<[String; 3]>> {
    let Some(doc) = att.attest(b"attest-self-check", &[], None)? else {
        return Ok(None);
    };
    let d = attest_core::nitro::verify_document(&doc)?;
    let pcrs = [d.pcr_hex(0), d.pcr_hex(1), d.pcr_hex(2)];
    ensure!(
        !pcrs.iter().all(|p| p.chars().all(|c| c == '0')),
        "this enclave runs in debug mode; it can't take part in a handoff"
    );
    Ok(Some(pcrs))
}

/// Check the other enclave's attestation: genuine Nitro, the same image as
/// this one, our nonce, and the expected key and user data.
fn check_peer(
    doc_b64: Option<&str>,
    mine: &Option<[String; 3]>,
    nonce: &[u8],
    public_key: &[u8],
    user_data: &[u8],
) -> Result<()> {
    let Some(mine) = mine else {
        // Dev mode: nothing is attested on either side.
        ensure!(doc_b64.is_none(), "a dev enclave can't take part in a handoff with a Nitro enclave");
        return Ok(());
    };
    let doc = b64().decode(doc_b64.context("the other enclave sent no attestation")?)?;
    let d = attest_core::nitro::verify_document(&doc)?;
    for (i, want) in mine.iter().enumerate() {
        ensure!(
            &d.pcr_hex(i) == want,
            "the other enclave runs a different image (PCR{i} {} vs ours {want})",
            d.pcr_hex(i)
        );
    }
    fn bytes<T: AsRef<[u8]>>(b: &Option<T>) -> Option<Vec<u8>> {
        b.as_ref().map(|x| x.as_ref().to_vec())
    }
    ensure!(bytes(&d.nonce).as_deref() == Some(nonce), "the attestation doesn't carry our nonce");
    ensure!(
        bytes(&d.public_key).as_deref() == Some(public_key),
        "the attestation doesn't carry the expected key"
    );
    ensure!(bytes(&d.user_data).as_deref() == Some(user_data), "the attestation covers something else");
    Ok(())
}

fn session_key(shared: &[u8], n_r: &[u8], r_pub: &[u8], g_pub: &[u8]) -> [u8; 32] {
    hash(&[KEY, shared, n_r, r_pub, g_pub])
}

/// The giving side: challenges, and the one handoff.
#[derive(Default)]
pub struct Giver {
    challenges: Mutex<Vec<([u8; 32], Instant)>>,
    done: AtomicBool,
    /// The operator's handoff token, from the parent's config. Anyone can
    /// run this image in their own enclave and pass the attestation check;
    /// that gains them nothing secret (it's this code), but a handoff stops
    /// this enclave serving, so only a request carrying the operator's
    /// token may trigger one. None: handoffs are off.
    token: Option<String>,
}

impl Giver {
    pub fn new(token: Option<String>) -> Self {
        Self { token: token.filter(|t| t.len() >= 16), ..Default::default() }
    }

    pub fn challenge(&self) -> Value {
        let n = random32();
        let mut c = self.challenges.lock().unwrap_or_else(|e| e.into_inner());
        c.retain(|(_, t)| t.elapsed() < Duration::from_secs(120));
        if c.len() >= 16 {
            c.remove(0);
        }
        c.push((n, Instant::now()));
        json!({"nonce": hex::encode(n)})
    }

    fn take_challenge(&self, n: &[u8; 32]) -> Result<()> {
        let mut c = self.challenges.lock().unwrap_or_else(|e| e.into_inner());
        let i = c
            .iter()
            .position(|(x, t)| x == n && t.elapsed() < Duration::from_secs(120))
            .context("unknown or expired challenge")?;
        c.remove(i);
        Ok(())
    }

    /// Check the successor, stop serving, write everything, and hand over.
    pub async fn give(
        &self,
        ctx: &Arc<crate::sessions::Ctx>,
        att: &Attester,
        body: &Value,
    ) -> Result<Value> {
        let Some(want) = &self.token else {
            anyhow::bail!("handoffs are not enabled on this enclave");
        };
        let got = body["token"].as_str().unwrap_or("");
        ensure!(
            got.len() == want.len() && ring::constant_time::verify_slices_are_equal(got.as_bytes(), want.as_bytes()).is_ok(),
            "wrong handoff token"
        );
        let n_g = hex32(&body["challenge"], "challenge")?;
        let r_pub = hex32(&body["public_key"], "public_key")?;
        let n_r = hex32(&body["nonce"], "nonce")?;
        self.take_challenge(&n_g)?;
        check_peer(
            body["document_b64"].as_str(),
            &own_pcrs(att)?,
            &n_g,
            &r_pub,
            &hash(&[REQUEST, &n_r]),
        )?;
        ensure!(
            !self.done.swap(true, Ordering::SeqCst),
            "this enclave already handed its sessions over"
        );
        // From here this enclave serves no session requests; everything it
        // has goes to the store, which then refuses its writes.
        ctx.moved.store(true, Ordering::SeqCst);
        let sessions = match ctx.store.write_all(&ctx.persist).await {
            Ok(s) => s,
            Err(e) => {
                ctx.moved.store(false, Ordering::SeqCst);
                self.done.store(false, Ordering::SeqCst);
                return Err(e.context("writing state before the handoff"));
            }
        };
        ctx.blobs.fence();
        let payload = serde_json::to_vec(&Payload {
            master_key: hex::encode(ctx.persist.keys.master()),
            signing_key: hex::encode(ctx.signing.to_bytes()),
            lineage_id: ctx.lineage.id.clone(),
            generation: ctx.lineage.generation,
            giver_boot: ctx.info.boot_id.clone(),
            sessions,
        })?;
        let rng = ring::rand::SystemRandom::new();
        let mine = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)
            .map_err(|_| anyhow!("key generation failed"))?;
        let g_pub = mine
            .compute_public_key()
            .map_err(|_| anyhow!("key generation failed"))?
            .as_ref()
            .to_vec();
        let key = agreement::agree_ephemeral(
            mine,
            &agreement::UnparsedPublicKey::new(&agreement::X25519, r_pub),
            |shared| session_key(shared, &n_r, &r_pub, &g_pub),
        )
        .map_err(|_| anyhow!("key agreement failed"))?;
        let ct = ChaCha20Poly1305::new(Key::from_slice(&key))
            .encrypt(Nonce::from_slice(&[0u8; 12]), AeadPayload { msg: &payload, aad: RESPONSE })
            .map_err(|_| anyhow!("encryption failed"))?;
        let user_data = hash(&[RESPONSE, &n_r, &r_pub, &g_pub, &attest_core::sha256(&ct)]);
        let doc = att.attest(&user_data, &g_pub, Some(&n_r))?;
        crate::log(&format!(
            "handoff: sessions handed to a successor ({} sessions); this enclave now only answers that they moved",
            ctx.store.len()
        ));
        Ok(json!({
            "public_key": hex::encode(&g_pub),
            "ciphertext": b64().encode(&ct),
            "document_b64": doc.map(|d| b64().encode(d)),
        }))
    }
}

/// `host[:port]`, port 443 unless given.
fn split_peer(peer: &str) -> Result<(String, u16)> {
    match peer.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') || h.starts_with('[') => Ok((h.trim_matches(['[', ']']).to_string(), p.parse()?)),
        _ => Ok((peer.to_string(), 443)),
    }
}

/// The receiving side: obtain the lineage from the enclave at `peer`.
pub async fn receive(net: &Net, att: &Attester, dev: bool, peer: &str, token: &str) -> Result<Payload> {
    let (host, port) = split_peer(peer)?;
    let https = !dev;
    let t = Duration::from_secs(60);
    let resp = net
        .request_peer("GET", https, &host, port, "/api/internal/handoff/challenge", vec![], t)
        .await?;
    ensure!(resp.status == 200, "the other enclave refused a challenge (HTTP {})", resp.status);
    let v: Value = serde_json::from_slice(&resp.body)?;
    let n_g = hex32(&v["nonce"], "nonce")?;

    let rng = ring::rand::SystemRandom::new();
    let mine = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)
        .map_err(|_| anyhow!("key generation failed"))?;
    let r_pub: [u8; 32] = mine
        .compute_public_key()
        .map_err(|_| anyhow!("key generation failed"))?
        .as_ref()
        .try_into()?;
    let n_r = random32();
    let doc = att.attest(&hash(&[REQUEST, &n_r]), &r_pub, Some(&n_g))?;
    let req = json!({
        "challenge": hex::encode(n_g),
        "public_key": hex::encode(r_pub),
        "nonce": hex::encode(n_r),
        "document_b64": doc.map(|d| b64().encode(d)),
        "token": token,
    });
    let resp = net
        .request_peer("POST", https, &host, port, "/api/internal/handoff", serde_json::to_vec(&req)?, t)
        .await?;
    let v: Value = serde_json::from_slice(&resp.body).unwrap_or(Value::Null);
    ensure!(
        resp.status == 200,
        "the other enclave refused the handoff (HTTP {}): {}",
        resp.status,
        v["error"].as_str().unwrap_or("")
    );
    let g_pub = hex32(&v["public_key"], "public_key")?;
    let ct = b64().decode(v["ciphertext"].as_str().context("no ciphertext")?)?;
    check_peer(
        v["document_b64"].as_str(),
        &own_pcrs(att)?,
        &n_r,
        &g_pub,
        &hash(&[RESPONSE, &n_r, &r_pub, &g_pub, &attest_core::sha256(&ct)]),
    )?;
    let key = agreement::agree_ephemeral(
        mine,
        &agreement::UnparsedPublicKey::new(&agreement::X25519, g_pub),
        |shared| session_key(shared, &n_r, &r_pub, &g_pub),
    )
    .map_err(|_| anyhow!("key agreement failed"))?;
    let plain = ChaCha20Poly1305::new(Key::from_slice(&key))
        .decrypt(Nonce::from_slice(&[0u8; 12]), AeadPayload { msg: &ct, aad: RESPONSE })
        .map_err(|_| anyhow!("the handoff payload failed authentication"))?;
    Ok(serde_json::from_slice(&plain)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peers() {
        assert_eq!(split_peer("203.0.113.5").unwrap(), ("203.0.113.5".into(), 443));
        assert_eq!(split_peer("127.0.0.1:38080").unwrap(), ("127.0.0.1".into(), 38080));
        assert_eq!(split_peer("attest.example.com").unwrap(), ("attest.example.com".into(), 443));
    }

    #[test]
    fn dev_and_nitro_dont_mix() {
        // A dev enclave refuses an attested peer, so a dev build can't be
        // used to pull keys from (or push state to) a real one.
        assert!(check_peer(Some("AAAA"), &None, b"n", b"k", b"u").is_err());
        assert!(check_peer(None, &None, b"n", b"k", b"u").is_ok());
        // A Nitro enclave insists on a document.
        let mine = Some(["1".repeat(96), "2".repeat(96), "3".repeat(96)]);
        assert!(check_peer(None, &mine, b"n", b"k", b"u").is_err());
        assert!(check_peer(Some("AAAA"), &mine, b"n", b"k", b"u").is_err());
    }
}
