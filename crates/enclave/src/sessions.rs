//! Sessions: two parties, one question, the auditee's code, and agent runs.
//!
//! A party is whoever holds the session's auditee or auditor link. All
//! state lives in enclave memory and is lost when the enclave restarts.
//!
//! Visibility, enforced here:
//!   auditee  sees everything: question, proposals (never keys), live agent
//!            trace, results before release, auditor follow-ups (blinded
//!            ones show only that a message was sent).
//!   auditor  sees the question flow, code metadata and affidavit, model
//!            choices, and each run's status; a run's verdict and
//!            certificate only after the auditee releases it.

use crate::bundle::Bundle;
use crate::llm::{self, Client, Turn};
use crate::run;
use anyhow::{anyhow, bail, ensure, Result};
use attest_core::harness::{self, MAX_STEPS_CAP};
use attest_core::*;
use ed25519_dalek::SigningKey;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;

pub const MAX_SESSIONS: usize = 2000;
pub const SESSION_TTL_MS: u64 = 30 * 24 * 3600 * 1000;
const MAX_QUESTION_CHARS: usize = 20_000;
const MAX_MESSAGE_CHARS: usize = 20_000;

/// Application context shared by every session.
pub struct Ctx {
    pub dev: bool,
    pub net: crate::net::Net,
    pub info: EnclaveInfo,
    pub info_json: String,
    pub boot_doc_b64: Option<String>,
    pub signing: SigningKey,
    pub email: Option<crate::notify::EmailConfig>,
    pub email_limiter: crate::notify::Limiter,
    pub blobs: crate::blobs::BlobClient,
    pub cache: Arc<crate::blobs::Cache>,
    pub upload_slots: tokio::sync::Semaphore,
    /// Compiled at boot in the background; None until ready (or if absent).
    pub sandbox: Arc<std::sync::OnceLock<Arc<crate::sandbox::Sandbox>>>,
    /// Domain, or public IP, the server is reached at (informational).
    pub public_name: Option<String>,
    pub max_code_bytes: usize,
    pub slots: tokio::sync::Semaphore,
    /// Python disclosures get their own slot, apart from runs.
    pub disclosure_slots: tokio::sync::Semaphore,
    pub store: Store,
}

#[derive(Default)]
pub struct Store {
    sessions: Mutex<HashMap<String, Arc<Session>>>,
    /// question text sha256 -> sessions that ran it
    text_index: Mutex<HashMap<String, HashSet<String>>>,
    last_sweep: std::sync::atomic::AtomicU64,
}

pub struct Session {
    pub id: String,
    pub created_at_ms: u64,
    token_hashes: [String; 2],
    st: Mutex<State>,
    /// Bumped on every change, so long-polls can wait for one.
    /// Change counters, one per role: [auditee, auditor]. Private changes
    /// (the live trace, auditee-only events) never touch the auditor's,
    /// so the auditor can't observe the run through them.
    tx: [watch::Sender<u64>; 2],
}

#[derive(Default)]
struct State {
    /// Set when the session is swept away; nothing new starts after that.
    expired: bool,
    versions: [u64; 2],
    auditor_joined: bool,
    questions: Vec<Question>,
    code: Option<Arc<Bundle>>,
    affidavit: Option<(String, AffidavitRecord)>,
    models: Vec<ModelProposal>,
    runs: Vec<RunState>,
    events: Vec<Event>,
    notify: HashMap<Role, NotifyPrefs>,
    event_counts: [u64; 2],
    disclosures: Vec<DisclosureState>,
    /// Drafts being prepared right now (counted against the limits).
    disclosures_in_flight: usize,
}

/// A disclosure starts as a draft only the auditee sees; publishing signs
/// it and shows it to the auditor.
struct DisclosureState {
    /// The auditee's handle for it. `body.number` is assigned only when it
    /// is published, so the auditor's numbering says nothing about drafts.
    draft: u32,
    body: DisclosureBody,
    /// draft | published | discarded
    status: &'static str,
    signed: Option<Disclosure>,
}

const MAX_DISCLOSURES: usize = 100;
/// Drafts one session may prepare at once.
const MAX_DISCLOSURES_IN_FLIGHT: usize = 2;
/// Content a session's drafts and published disclosures may hold in total.
const MAX_DISCLOSURE_BYTES: usize = 16 << 20;

fn disclosure_bytes(c: &DisclosureContent) -> usize {
    match c {
        DisclosureContent::File { text, base64, .. } => {
            text.as_ref().map_or(0, |t| t.len()) + base64.as_ref().map_or(0, |b| b.len())
        }
        DisclosureContent::Python { code, stdout, stderr, files_opened, .. } => {
            code.len()
                + stdout.len()
                + stderr.len()
                + files_opened.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>()
        }
    }
}

/// Undoes a disclosure reservation however the request ends.
struct DisclosureReservation(Arc<Session>);

impl Drop for DisclosureReservation {
    fn drop(&mut self) {
        let mut st = lock(&self.0.st);
        st.disclosures_in_flight = st.disclosures_in_flight.saturating_sub(1);
    }
}
const MAX_DISCLOSED_FILE: u64 = 1 << 20;
const MAX_SCRIPT_BYTES: usize = 100_000;

#[derive(Clone, Serialize)]
struct Question {
    version: u32,
    text: String,
    max_steps: u32,
    allow_fine_tuned: bool,
    answer_format: AnswerFormat,
    asked_at_ms: u64,
    /// proposed | accepted | rejected | superseded
    status: &'static str,
    note: Option<String>,
    decided_at_ms: Option<u64>,
}

struct ModelProposal {
    id: u32,
    by: Role,
    provider: Provider,
    model: String,
    api_key: String,
    /// OpenRouter only: required zero data retention and allowed upstream hosts.
    routing: llm::Routing,
    /// Host, API shape, and for the clouds the region, project or resource.
    target: llm::Target,
    /// "builtin", or a jailed harness: "codex", "claude-code", "pi".
    agent: String,
    /// Whose provider account the key belongs to.
    key_from: Role,
    /// pending | approved | rejected | superseded
    status: &'static str,
    proposed_at_ms: u64,
    decided_at_ms: Option<u64>,
    note: Option<String>,
}

impl ModelProposal {
    fn public(&self) -> Value {
        json!({
            "id": self.id, "proposed_by": self.by, "provider": self.provider, "model": self.model, "agent": self.agent,
            "has_key": !self.api_key.is_empty(), "key_from": self.key_from,
            "openrouter_zdr": self.routing.zdr, "openrouter_only": self.routing.only, "status": self.status,
            "endpoint": self.target.describe(), "params": self.target.params(),
            "fine_tuned": llm::is_fine_tuned(self.provider, &self.model),
            "proposed_at_ms": self.proposed_at_ms, "decided_at_ms": self.decided_at_ms, "note": self.note,
        })
    }
}

struct RunState {
    id: String,
    number: u32,
    parent: Option<String>,
    question_version: u32,
    model_id: u32,
    tree: String,
    commitment: String,
    /// Every auditor message in this conversation, including inherited ones.
    messages: Vec<(MessageRecord, String)>,
    /// running | awaiting_release | released | declined
    status: &'static str,
    steps: u32,
    trace: Vec<Value>,
    /// Bytes in `trace` (counted in TRACE_BYTES), and whether it hit its cap.
    trace_bytes: usize,
    trace_full: bool,
    turns: Option<Vec<Turn>>,
    /// Everything about the finished run, for the auditee. Nothing from it
    /// reaches the auditor except through `certificate`.
    full: Option<CertificateBody>,
    /// Signed at release, with what the auditee chose to release.
    certificate: Option<Certificate>,
    verdict: Option<Verdict>,
    outcome: Option<Outcome>,
    decision_note: Option<String>,
    started_at_ms: u64,
    finished_at_ms: Option<u64>,
    decided_at_ms: Option<u64>,
}

#[derive(Clone, Serialize)]
struct Event {
    /// This event's number in each role's own feed (0: not shown to it),
    /// so private events leave no gaps in the other party's numbering.
    #[serde(skip)]
    seqs: [u64; 2],
    seq: u64,
    at_ms: u64,
    kind: String,
    text: String,
    #[serde(skip)]
    important: bool,
}

#[derive(Clone, Default, Serialize)]
pub struct NotifyPrefs {
    pub email: Option<String>,
    /// none | checking | pending (confirmation email sent) | verified | rate_limited | error
    pub email_status: String,
    #[serde(skip)]
    changes: u32,
}

const MAX_EMAIL_CHANGES: u32 = 5;

fn ri(role: Role) -> usize {
    match role {
        Role::Auditee => 0,
        Role::Auditor => 1,
    }
}

fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    hex::encode(b)
}

/// A trimmed, non-empty string field of at most `max` bytes.
fn field(v: &Value, key: &str, max: usize) -> Result<Option<String>> {
    let s = clean(v[key].as_str());
    if let Some(s) = &s {
        ensure!(s.len() <= max, "{key} is over {max} bytes");
    }
    Ok(s)
}

const MAX_NOTE_BYTES: usize = 4000;
const MAX_NAME_BYTES: usize = 500;
/// Per session, so its retained state stays bounded.
const MAX_QUESTION_VERSIONS: usize = 100;
const MAX_MODEL_PROPOSALS: usize = 50;
const MAX_RUNS: usize = 50;
/// Trace kept for one run, and for all runs on the server.
const MAX_TRACE_BYTES_PER_RUN: usize = 8 << 20;
const MAX_TRACE_BYTES_TOTAL: usize = 2 << 30;
static TRACE_BYTES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn clean(s: Option<&str>) -> Option<String> {
    s.map(|x| x.trim().to_string()).filter(|x| !x.is_empty())
}

/// Lock a mutex even if a thread panicked while holding it. A panic is a bug
/// to fix, but it shouldn't make every later request in that session (or,
/// for the global map, on the server) fail too.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// A session nobody has used (no question, no code) is dropped after this,
/// and is the first to go when the server is full, so creating empty
/// sessions can't lock others out.
const IDLE_SESSION_TTL_MS: u64 = 24 * 3600 * 1000;

impl Session {
    fn expired(&self, now: u64) -> bool {
        now.saturating_sub(self.created_at_ms) >= SESSION_TTL_MS
    }

    fn idle(&self) -> bool {
        let st = lock(&self.st);
        st.questions.is_empty() && st.code.is_none()
    }
}

impl Store {
    /// Drop expired sessions (and idle ones past their shorter limit), at
    /// most once a minute; called on every request. Sessions are taken out
    /// of the map first and cleaned up after its lock is released.
    pub fn sweep(&self) {
        let now = now_ms();
        let last = self.last_sweep.load(std::sync::atomic::Ordering::Relaxed);
        if now.saturating_sub(last) < 60_000
            || self
                .last_sweep
                .compare_exchange(last, now, std::sync::atomic::Ordering::Relaxed, std::sync::atomic::Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        let snapshot: Vec<Arc<Session>> = lock(&self.sessions).values().cloned().collect();
        let gone: Vec<Arc<Session>> = snapshot
            .into_iter()
            .filter(|s| {
                s.expired(now)
                    || (now.saturating_sub(s.created_at_ms) >= IDLE_SESSION_TTL_MS && s.idle())
            })
            .collect();
        self.remove(&gone);
    }

    fn remove(&self, gone: &[Arc<Session>]) {
        if gone.is_empty() {
            return;
        }
        {
            let mut map = lock(&self.sessions);
            for s in gone {
                map.remove(&s.id);
            }
        }
        {
            let mut idx = lock(&self.text_index);
            for set in idx.values_mut() {
                for s in gone {
                    set.remove(&s.id);
                }
            }
            idx.retain(|_, set| !set.is_empty());
        }
        for s in gone {
            let mut st = lock(&s.st);
            // Runs still going hold their own reference to the code; it's
            // discarded once they end (see RunJob).
            if let Some(b) = st.code.take() {
                tokio::spawn(async move { b.discard().await });
            }
            st.expired = true;
            let freed: usize = st.runs.iter().map(|r| r.trace_bytes).sum();
            TRACE_BYTES.fetch_sub(freed.min(TRACE_BYTES.load(std::sync::atomic::Ordering::Relaxed)), std::sync::atomic::Ordering::Relaxed);
            // The session is gone from the map; drop what it held.
            st.runs.clear();
            st.disclosures.clear();
        }
    }

    pub fn create(&self) -> Result<(Arc<Session>, String, String)> {
        self.sweep();
        let now = now_ms();
        let full = lock(&self.sessions).len() >= MAX_SESSIONS;
        if full {
            // Make room by dropping the oldest session nobody has used.
            let snapshot: Vec<Arc<Session>> = lock(&self.sessions).values().cloned().collect();
            let oldest_idle = snapshot
                .into_iter()
                .filter(|s| s.idle())
                .min_by_key(|s| s.created_at_ms);
            if let Some(s) = oldest_idle {
                self.remove(&[s]);
            }
        }
        let mut map = lock(&self.sessions);
        ensure!(
            map.len() < MAX_SESSIONS,
            "this server is at its session limit; try again later"
        );
        let auditee = random_hex(32);
        let auditor = random_hex(32);
        let tx = [watch::channel(0).0, watch::channel(0).0];
        let s = Arc::new(Session {
            id: random_hex(16),
            created_at_ms: now,
            token_hashes: [
                sha256_hex(auditee.as_bytes()),
                sha256_hex(auditor.as_bytes()),
            ],
            st: Mutex::new(State::default()),
            tx,
        });
        map.insert(s.id.clone(), s.clone());
        Ok((s, auditee, auditor))
    }

    /// Find the session and the role a token grants. Unknown session and bad
    /// token are indistinguishable.
    pub fn auth(&self, id: &str, token: &str) -> Result<(Arc<Session>, Role)> {
        self.sweep();
        let s = lock(&self.sessions)
            .get(id)
            .cloned()
            .filter(|s| !s.expired(now_ms()));
        let h = sha256_hex(token.as_bytes());
        if let Some(s) = s {
            if h == s.token_hashes[0] {
                return Ok((s, Role::Auditee));
            }
            if h == s.token_hashes[1] {
                return Ok((s, Role::Auditor));
            }
        }
        bail!("unknown session or wrong link")
    }

    pub fn get(&self, id: &str) -> Option<Arc<Session>> {
        lock(&self.sessions).get(id).cloned()
    }

    fn note_text_run(&self, text_sha: &str, session: &str) -> u32 {
        let mut idx = lock(&self.text_index);
        let set = idx.entry(text_sha.to_string()).or_default();
        let others = set.iter().filter(|s| *s != session).count() as u32;
        set.insert(session.to_string());
        others
    }
}

impl Session {
    pub fn subscribe(&self, role: Role) -> watch::Receiver<u64> {
        self.tx[ri(role)].subscribe()
    }

    /// A change both parties may observe.
    fn changed(&self, st: &mut State) {
        self.changed_for(st, Role::Auditee);
        self.changed_for(st, Role::Auditor);
    }

    /// A change only `role` may observe.
    fn changed_for(&self, st: &mut State, role: Role) {
        let i = ri(role);
        st.versions[i] += 1;
        // send_replace stores the value even when nobody is waiting, so a
        // long-poll that subscribes later sees it at once.
        self.tx[i].send_replace(st.versions[i]);
    }

    /// Email `role` now, if they asked for email.
    fn email(&self, ctx: &Arc<Ctx>, role: Role, text: String) {
        let prefs = lock(&self.st).notify.get(&role).cloned();
        if let Some(NotifyPrefs {
            email: Some(email),
            email_status,
            ..
        }) = prefs
        {
            let verified = email_status == "verified";
            tokio::spawn(crate::notify::deliver(
                ctx.clone(),
                self.id.clone(),
                role,
                email,
                verified,
                text,
            ));
        }
    }

    /// Record an event, wake long-polls, and notify the parties it concerns
    /// (never the party who caused it).
    fn event(
        &self,
        ctx: &Arc<Ctx>,
        st: &mut State,
        kind: &str,
        text: String,
        to: Option<Role>,
        by: Option<Role>,
        important: bool,
    ) {
        let mut seqs = [0u64; 2];
        for r in [Role::Auditee, Role::Auditor] {
            if to.map_or(true, |t| t == r) {
                st.event_counts[ri(r)] += 1;
                seqs[ri(r)] = st.event_counts[ri(r)];
            }
        }
        let ev = Event {
            seqs,
            seq: 0,
            at_ms: now_ms(),
            kind: kind.into(),
            text,
            important,
        };
        st.events.push(ev.clone());
        match to {
            Some(r) => self.changed_for(st, r),
            None => self.changed(st),
        }
        for role in [Role::Auditee, Role::Auditor] {
            if Some(role) == by || to.is_some_and(|t| t != role) {
                continue;
            }
            if let (
                true,
                Some(NotifyPrefs {
                    email: Some(email),
                    email_status,
                    ..
                }),
            ) = (ev.important, st.notify.get(&role).cloned())
            {
                let verified = email_status == "verified";
                tokio::spawn(crate::notify::deliver(
                    ctx.clone(),
                    self.id.clone(),
                    role,
                    email,
                    verified,
                    ev.text.clone(),
                ));
            }
        }
    }

    // ------------------------------------------------------------ actions

    pub fn touch(&self, ctx: &Arc<Ctx>, role: Role) {
        let mut st = lock(&self.st);
        if role == Role::Auditor && !st.auditor_joined {
            st.auditor_joined = true;
            self.event(
                ctx,
                &mut st,
                "auditor_joined",
                "The auditor opened the session.".into(),
                Some(Role::Auditee),
                Some(role),
                false,
            );
        }
    }

    pub fn propose_question(
        self: &Arc<Self>,
        ctx: &Arc<Ctx>,
        role: Role,
        v: &Value,
    ) -> Result<Value> {
        ensure!(role == Role::Auditor, "only the auditor asks the question");
        let text = clean(v["text"].as_str()).ok_or_else(|| anyhow!("text is required"))?;
        ensure!(
            text.chars().count() <= MAX_QUESTION_CHARS,
            "question is too long"
        );
        let max_steps = v["max_steps"]
            .as_u64()
            .unwrap_or(150)
            .clamp(1, MAX_STEPS_CAP as u64) as u32;
        let allow_fine_tuned = v["allow_fine_tuned"].as_bool().unwrap_or(false);
        let answer_format: AnswerFormat = match v.get("answer_format").filter(|f| !f.is_null()) {
            Some(f) => {
                serde_json::from_value(f.clone()).map_err(|e| anyhow!("answer_format: {e}"))?
            }
            None => AnswerFormat::default(),
        };
        answer_format
            .validate()
            .map_err(|e| anyhow!("answer_format: {e}"))?;
        let mut st = lock(&self.st);
        ensure!(
            st.questions.len() < MAX_QUESTION_VERSIONS,
            "this session has {MAX_QUESTION_VERSIONS} question versions already; start a new session"
        );
        for q in st.questions.iter_mut().filter(|q| q.status == "proposed") {
            q.status = "superseded";
        }
        let version = st.questions.len() as u32 + 1;
        st.questions.push(Question {
            version,
            text,
            max_steps,
            allow_fine_tuned,
            answer_format,
            asked_at_ms: now_ms(),
            status: "proposed",
            note: None,
            decided_at_ms: None,
        });
        let msg = if version == 1 {
            "The auditor asked a question.".to_string()
        } else {
            format!("The auditor revised the question (version {version}).")
        };
        self.event(
            ctx,
            &mut st,
            "question_proposed",
            msg,
            None,
            Some(role),
            true,
        );
        Ok(json!({"version": version}))
    }

    pub fn decide_question(
        self: &Arc<Self>,
        ctx: &Arc<Ctx>,
        role: Role,
        v: &Value,
    ) -> Result<Value> {
        ensure!(
            role == Role::Auditee,
            "only the auditee accepts or rejects the question"
        );
        let accept = v["accept"]
            .as_bool()
            .ok_or_else(|| anyhow!("accept (true/false) is required"))?;
        let version = v["version"]
            .as_u64()
            .ok_or_else(|| anyhow!("version is required"))? as u32;
        let note = field(v, "note", MAX_NOTE_BYTES)?;
        let mut st = lock(&self.st);
        let q = st
            .questions
            .last_mut()
            .ok_or_else(|| anyhow!("no question yet"))?;
        ensure!(
            q.version == version,
            "question version {version} is not the current one ({})",
            q.version
        );
        ensure!(
            q.status == "proposed",
            "question {version} was already {}",
            q.status
        );
        q.status = if accept { "accepted" } else { "rejected" };
        q.note = note.clone();
        q.decided_at_ms = Some(now_ms());
        let msg = match (accept, &note) {
            (true, _) => format!("The auditee accepted question version {version}."),
            (false, Some(n)) => format!("The auditee rejected question version {version}: {n}"),
            (false, None) => format!("The auditee rejected question version {version}."),
        };
        self.event(
            ctx,
            &mut st,
            "question_decided",
            msg,
            None,
            Some(role),
            true,
        );
        self.maybe_start(ctx, &mut st);
        Ok(json!({"ok": true}))
    }

    /// Install a freshly ingested bundle, replacing (and discarding) any earlier one.
    pub fn set_code(self: &Arc<Self>, ctx: &Arc<Ctx>, role: Role, bundle: Bundle) -> Result<Value> {
        ensure!(role == Role::Auditee, "only the auditee uploads code");
        let bundle = Arc::new(bundle);
        let info = bundle.info.clone();
        let mut st = lock(&self.st);
        if let Some(old) = st.code.replace(bundle) {
            // Runs still holding it keep working; blobs go once nothing does.
            if Arc::strong_count(&old) == 1 {
                tokio::spawn(async move { old.discard().await });
            }
        }
        let had_affidavit = st.affidavit.take().is_some();
        // Shown to both sides, so only the commitment: size and tree hash
        // stay with the auditee until a release.
        let msg = format!(
            "The auditee uploaded code (commitment {}){}.",
            &info.commitment_sha256[..12],
            if had_affidavit {
                " (replacing earlier code; the affidavit must be confirmed again)"
            } else {
                ""
            }
        );
        self.event(ctx, &mut st, "code_uploaded", msg, None, Some(role), false);
        Ok(serde_json::to_value(&info)?)
    }

    pub fn confirm_affidavit(
        self: &Arc<Self>,
        ctx: &Arc<Ctx>,
        role: Role,
        v: &Value,
    ) -> Result<Value> {
        ensure!(
            role == Role::Auditee,
            "only the auditee confirms the affidavit"
        );
        let organization =
            field(v, "organization", MAX_NAME_BYTES)?.ok_or_else(|| anyhow!("organization is required"))?;
        let repo_url = field(v, "repo_url", MAX_NAME_BYTES)?;
        let git_commit = field(v, "git_commit", MAX_NAME_BYTES)?;
        let tree = clean(v["tree_sha256"].as_str())
            .ok_or_else(|| anyhow!("tree_sha256 of the uploaded code is required"))?;
        let mut st = lock(&self.st);
        let code = st
            .code
            .as_ref()
            .ok_or_else(|| anyhow!("upload code first"))?;
        ensure!(
            code.info.tree_sha256 == tree,
            "the uploaded code has tree {}, not {tree}",
            code.info.tree_sha256
        );
        let rec = AffidavitRecord {
            statement: affidavit_statement(
                &organization,
                &code.info.commitment_sha256,
                repo_url.as_deref(),
                git_commit.as_deref(),
            ),
            organization,
            repo_url,
            git_commit,
            confirmed_at_ms: now_ms(),
        };
        st.affidavit = Some((tree, rec.clone()));
        self.event(
            ctx,
            &mut st,
            "affidavit_confirmed",
            format!(
                "The auditee confirmed the affidavit for {}.",
                rec.organization
            ),
            None,
            Some(role),
            false,
        );
        self.maybe_start(ctx, &mut st);
        Ok(serde_json::to_value(&rec)?)
    }

    pub fn propose_model(self: &Arc<Self>, ctx: &Arc<Ctx>, role: Role, v: &Value) -> Result<Value> {
        let provider: Provider = v["provider"].as_str().unwrap_or_default().parse()?;
        ensure!(
            provider != Provider::Mock || ctx.dev,
            "the mock provider is only available in dev mode"
        );
        let model = clean(v["model"].as_str()).ok_or_else(|| anyhow!("model is required"))?;
        crate::llm::vet_model(provider, &model)?;
        // The auditee always supplies a key. The auditor may propose a model
        // without one (the auditee then supplies theirs when approving).
        let api_key = clean(v["api_key"].as_str()).unwrap_or_default();
        ensure!(
            role == Role::Auditor || !api_key.is_empty(),
            "api_key is required"
        );
        let mock_endpoint = field(v, "mock_endpoint", MAX_NAME_BYTES)?;
        let target = llm::Target::resolve(provider, &model, v, mock_endpoint.as_deref())?;
        if !api_key.is_empty() {
            llm::Creds::check(&target, &api_key)?;
        }
        let only: Vec<String> = match &v["openrouter_only"] {
            Value::Null => vec![],
            Value::Array(a) => a
                .iter()
                .map(|h| {
                    h.as_str()
                        .map(|s| s.trim().to_ascii_lowercase())
                        .ok_or_else(|| anyhow!("openrouter_only must be a list of strings"))
                })
                .collect::<Result<_>>()?,
            _ => anyhow::bail!("openrouter_only must be a list of strings"),
        };
        llm::vet_routing(provider, &only)?;
        let routing = llm::Routing {
            zdr: provider == Provider::Openrouter && v["openrouter_zdr"].as_bool().unwrap_or(false),
            only,
        };
        let agent = clean(v["agent"].as_str()).unwrap_or_else(|| "builtin".into());
        crate::harnesses::supports(&agent, &target)?;
        ensure!(
            provider != Provider::Mock || mock_endpoint.is_some(),
            "mock_endpoint is required for the mock provider"
        );
        let api_key_given = !api_key.is_empty();
        let mut st = lock(&self.st);
        ensure!(
            st.models.len() < MAX_MODEL_PROPOSALS,
            "this session has {MAX_MODEL_PROPOSALS} model proposals already; start a new session"
        );
        let id = st.models.len() as u32 + 1;
        // The auditee's own proposal needs no approval.
        let approved = role == Role::Auditee;
        if approved {
            for m in st
                .models
                .iter_mut()
                .filter(|m| m.status == "approved" || m.status == "pending")
            {
                m.status = "superseded";
            }
        }
        st.models.push(ModelProposal {
            id,
            by: role,
            provider,
            model: model.clone(),
            api_key,
            routing,
            target,
            agent: agent.clone(),
            key_from: role,
            status: if approved { "approved" } else { "pending" },
            proposed_at_ms: now_ms(),
            decided_at_ms: approved.then(now_ms),
            note: None,
        });
        let msg = if approved {
            format!(
                "The auditee chose {} / {model}{}.",
                provider.as_str(),
                if agent == "builtin" {
                    String::new()
                } else {
                    format!(" with {agent}")
                }
            )
        } else {
            format!(
                "The auditor proposed {} / {model}{}{}; the auditee must approve it.",
                provider.as_str(),
                if agent == "builtin" {
                    String::new()
                } else {
                    format!(" with {agent}")
                },
                if api_key_given {
                    " with their own API key"
                } else {
                    " (the auditee supplies the key)"
                }
            )
        };
        self.event(
            ctx,
            &mut st,
            "model_proposed",
            msg,
            None,
            Some(role),
            !approved,
        );
        self.maybe_start(ctx, &mut st);
        Ok(json!({"id": id, "status": if approved { "approved" } else { "pending" }}))
    }

    pub fn decide_model(
        self: &Arc<Self>,
        ctx: &Arc<Ctx>,
        role: Role,
        id: u32,
        v: &Value,
    ) -> Result<Value> {
        ensure!(role == Role::Auditee, "only the auditee approves models");
        let approve = v["approve"]
            .as_bool()
            .ok_or_else(|| anyhow!("approve (true/false) is required"))?;
        let note = field(v, "note", MAX_NOTE_BYTES)?;
        let own_key = clean(v["api_key"].as_str());
        let mut st = lock(&self.st);
        ensure!(
            st.models
                .iter()
                .any(|m| m.id == id && m.status == "pending"),
            "model proposal {id} is not pending"
        );
        if approve {
            let m = st.models.iter().find(|m| m.id == id).unwrap();
            if own_key.is_none() {
                ensure!(
                    !m.api_key.is_empty(),
                    "this proposal has no API key: supply yours (api_key) to approve it"
                );
                ensure!(
                    v["accept_auditor_account"].as_bool() == Some(true),
                    "this proposal uses the auditor's own provider account, which may log everything the model sees, including your code. \
                     Supply your own api_key instead, or pass accept_auditor_account: true to accept that"
                );
            }
        }
        if approve {
            for m in st.models.iter_mut().filter(|m| m.status == "approved") {
                m.status = "superseded";
            }
        }
        let m = st.models.iter_mut().find(|m| m.id == id).unwrap();
        if let (true, Some(k)) = (approve, own_key) {
            // On a cloud, the region, project or resource decides whose
            // account receives the requests, so it comes with the key: the
            // auditor's project with the auditee's credentials could still
            // log everything there.
            let target = if m.target.has_account_params() {
                llm::Target::resolve(m.provider, &m.model, v, None).map_err(|e| {
                    anyhow!(
                        "with your own key, also give your own {} ({e})",
                        match m.provider {
                            Provider::Bedrock => "region",
                            Provider::Vertex => "project and location",
                            _ => "resource and api",
                        }
                    )
                })?
            } else {
                m.target.clone()
            };
            llm::Creds::check(&target, &k)?;
            m.target = target;
            m.api_key = k;
            m.key_from = Role::Auditee;
        }
        m.status = if approve { "approved" } else { "rejected" };
        m.decided_at_ms = Some(now_ms());
        m.note = note.clone();
        let label = format!("{} / {}", m.provider.as_str(), m.model);
        let msg = match (approve, note) {
            (true, _) => format!("The auditee approved {label}."),
            (false, Some(n)) => format!("The auditee rejected {label}: {n}"),
            (false, None) => format!("The auditee rejected {label}."),
        };
        self.event(ctx, &mut st, "model_decided", msg, None, Some(role), true);
        self.maybe_start(ctx, &mut st);
        Ok(json!({"ok": true}))
    }

    pub fn decide_release(
        self: &Arc<Self>,
        ctx: &Arc<Ctx>,
        role: Role,
        run_id: &str,
        v: &Value,
    ) -> Result<Value> {
        ensure!(role == Role::Auditee, "only the auditee releases results");
        let release = v["release"]
            .as_bool()
            .ok_or_else(|| anyhow!("release (true/false) is required"))?;
        let note = field(v, "note", MAX_NOTE_BYTES)?;
        let details = v["details"].as_bool().unwrap_or(false);
        let mut st = lock(&self.st);
        let strict = st.questions.last().map(|q| q.answer_format.is_strict());
        let r = st
            .runs
            .iter_mut()
            .find(|r| r.id == run_id)
            .ok_or_else(|| anyhow!("no such run"))?;
        ensure!(
            r.status == "awaiting_release",
            "run {} is {}",
            r.number,
            r.status
        );
        if release {
            let full = r.full.as_ref().ok_or_else(|| anyhow!("run {} has no result", r.number))?;
            let strict = strict.unwrap_or(false) || full.manifest.question.answer_format.is_strict();
            let body = public_body(full, details, strict);
            r.certificate = Some(sign_certificate(ctx, &body)?);
        }
        r.status = if release { "released" } else { "declined" };
        r.decided_at_ms = Some(now_ms());
        r.decision_note = note.clone();
        let n = r.number;
        let msg = match (release, note) {
            (true, _) => format!("The auditee released the result of run {n}."),
            (false, Some(x)) => format!("The auditee declined to release run {n}: {x}"),
            (false, None) => format!("The auditee declined to release run {n}."),
        };
        self.event(ctx, &mut st, "release_decided", msg, None, Some(role), true);
        Ok(json!({"ok": true}))
    }

    pub fn followup(
        self: &Arc<Self>,
        ctx: &Arc<Ctx>,
        role: Role,
        run_id: &str,
        v: &Value,
    ) -> Result<Value> {
        ensure!(
            role == Role::Auditor,
            "only the auditor sends follow-up messages"
        );
        let text = clean(v["text"].as_str()).ok_or_else(|| anyhow!("text is required"))?;
        ensure!(
            text.chars().count() <= MAX_MESSAGE_CHARS,
            "message is too long"
        );
        let blinded = v["blinded"].as_bool().unwrap_or(false);
        let mut st = lock(&self.st);
        ensure!(
            !busy_for(&st, role),
            "wait until the current run is released or declined"
        );
        let parent = st
            .runs
            .iter()
            .find(|r| r.id == run_id)
            .ok_or_else(|| anyhow!("no such run"))?;
        ensure!(
            parent.status == "released" || parent.status == "declined",
            "follow-ups are possible after the auditee decides on run {}",
            parent.number
        );
        let model = st.models.iter().find(|m| m.id == parent.model_id).unwrap();
        ensure!(model.status != "rejected", "that run's model was rejected");
        let rec = MessageRecord {
            sent_at_ms: now_ms(),
            blinded,
            text_sha256: sha256_hex(text.as_bytes()),
            text: (!blinded).then(|| text.clone()),
        };
        let spec = RunSpec {
            question_version: parent.question_version,
            model_id: parent.model_id,
            parent: Some(parent.id.clone()),
            message: Some((rec, text)),
        };
        let id = self.start_run(ctx, &mut st, spec)?;
        Ok(json!({"run_id": id}))
    }

    /// Set (or clear) this role's notification email. A new address gets
    /// one confirmation email from SES; nothing else is sent until it's confirmed.
    pub fn set_notify(&self, ctx: &Arc<Ctx>, role: Role, v: &Value) -> Result<Value> {
        let email = clean(v["email"].as_str()).map(|e| e.to_ascii_lowercase());
        if let Some(e) = &email {
            ensure!(
                ctx.email.is_some(),
                "email is not configured on this server; poll the session instead"
            );
            let valid = e.len() < 254
                && e.split('@').count() == 2
                && e.split('@').all(|p| !p.is_empty())
                && e.contains('.')
                && !e.contains(|c: char| c.is_whitespace() || c == ',' || c == '<' || c == '>');
            ensure!(valid, "that does not look like an email address");
        }
        let mut st = lock(&self.st);
        let prefs = st.notify.entry(role).or_default();
        if prefs.email == email {
            return Ok(serde_json::to_value(prefs.clone())?);
        }
        ensure!(
            prefs.changes < MAX_EMAIL_CHANGES,
            "the email address for this session can't be changed again"
        );
        prefs.changes += 1;
        prefs.email = email.clone();
        prefs.email_status = if email.is_some() { "checking" } else { "none" }.into();
        let out = serde_json::to_value(prefs.clone())?;
        self.changed_for(&mut st, role);
        if let Some(e) = email {
            tokio::spawn(crate::notify::verify(ctx.clone(), self.id.clone(), role, e));
        }
        Ok(out)
    }

    pub fn set_email_status(&self, role: Role, email: &str, status: &str) {
        let mut st = lock(&self.st);
        if let Some(p) = st.notify.get_mut(&role) {
            if p.email.as_deref() == Some(email) {
                p.email_status = status.into();
                self.changed_for(&mut st, role);
            }
        }
    }

    // ------------------------------------------------------------ runs

    /// Start a run when the question is accepted, the code and affidavit are
    /// in place, and a model is approved, unless that combination already ran.
    fn maybe_start(self: &Arc<Self>, ctx: &Arc<Ctx>, st: &mut State) {
        if st.expired {
            return;
        }
        let Some(q) = st.questions.last() else { return };
        // Not while a run awaits the auditee's decision either: a new run
        // starting would tell the auditor when the earlier one finished.
        if q.status != "accepted"
            || st
                .runs
                .iter()
                .any(|r| r.status == "running" || r.status == "awaiting_release")
        {
            return;
        }
        let Some(code) = &st.code else { return };
        let Some((tree, _)) = &st.affidavit else {
            return;
        };
        if tree != &code.info.tree_sha256 {
            return;
        }
        let Some(m) = st.models.iter().rev().find(|m| m.status == "approved") else {
            return;
        };
        if llm::is_fine_tuned(m.provider, &m.model) && !q.allow_fine_tuned {
            return;
        }
        let (qv, mid) = (q.version, m.id);
        if st.runs.iter().any(|r| {
            r.parent.is_none() && r.question_version == qv && r.model_id == mid && &r.tree == tree
        }) {
            return;
        }
        let spec = RunSpec {
            question_version: qv,
            model_id: mid,
            parent: None,
            message: None,
        };
        if let Err(e) = self.start_run(ctx, st, spec) {
            crate::log(&format!("session {}: could not start run: {e:#}", self.id));
        }
    }

    fn start_run(
        self: &Arc<Self>,
        ctx: &Arc<Ctx>,
        st: &mut State,
        spec: RunSpec,
    ) -> Result<String> {
        ensure!(
            st.runs.len() < MAX_RUNS,
            "this session has had {MAX_RUNS} runs; start a new session"
        );
        let q = st
            .questions
            .iter()
            .find(|q| q.version == spec.question_version)
            .cloned()
            .ok_or_else(|| anyhow!("no question"))?;
        let bundle = st.code.clone().ok_or_else(|| anyhow!("no code"))?;
        let (_, affidavit) = st
            .affidavit
            .clone()
            .ok_or_else(|| anyhow!("no affidavit"))?;
        let m = st
            .models
            .iter()
            .find(|m| m.id == spec.model_id)
            .ok_or_else(|| anyhow!("no model"))?;
        let client = Client::new(
            ctx.net.clone(),
            m.target.clone(),
            m.model.clone(),
            m.api_key.clone(),
            m.routing.clone(),
        )?;
        let model_info = ModelInfo {
            provider: m.provider,
            endpoint: m.target.describe(),
            requested_model: m.model.clone(),
            fine_tuned: llm::is_fine_tuned(m.provider, &m.model),
            proposed_by: m.by,
            approved_at_ms: m.decided_at_ms.unwrap_or(m.proposed_at_ms),
            response_models: vec![],
            key_owner: None,
            upstream_providers: vec![],
            openrouter_zdr: (m.provider == Provider::Openrouter).then_some(m.routing.zdr),
            openrouter_only: m.routing.only.clone(),
            agent: crate::harnesses::Agent::parse(&m.agent)
                .map(|a| a.label())
                .unwrap_or_else(|| "builtin".into()),
            key_from: Some(m.key_from),
        };
        let harness_job = crate::harnesses::Agent::parse(&m.agent).map(|agent| {
            (
                agent,
                m.target.clone(),
                m.model.clone(),
                m.api_key.clone(),
                m.routing.clone(),
            )
        });

        let (mut turns, mut messages, mut trace) = (Vec::new(), Vec::new(), Vec::new());
        let mut previous_verdict = None;
        match &spec.parent {
            Some(pid) => {
                let parent = st
                    .runs
                    .iter()
                    .find(|r| &r.id == pid)
                    .ok_or_else(|| anyhow!("no parent run"))?;
                if harness_job.is_some() {
                    previous_verdict = parent.verdict.clone();
                } else {
                    turns = parent
                        .turns
                        .clone()
                        .ok_or_else(|| anyhow!("parent run has no conversation to continue"))?;
                }
                messages = parent.messages.clone();
            }
            None => {
                trace.push(json!({"type": "system", "content": harness::SYSTEM_PROMPT}));
                let p = harness::user_prompt(
                    &q.text,
                    bundle.info.file_count,
                    bundle.info.total_bytes,
                    &q.answer_format,
                );
                trace.push(json!({"type": "user", "content": p}));
                turns.push(Turn::User(p));
            }
        }
        if let Some((rec, text)) = &spec.message {
            trace.push(
                json!({"type": "auditor_message", "blinded": rec.blinded, "content": rec.text}),
            );
            turns.push(Turn::User(harness::followup_prompt(text)));
            messages.push((rec.clone(), text.clone()));
        }

        let text_sha = sha256_hex(q.text.as_bytes());
        let mut prior_trees: Vec<String> = st.runs.iter().map(|r| r.tree.clone()).collect();
        prior_trees.sort();
        prior_trees.dedup();
        let history = History {
            prior_runs_in_session: st.runs.len() as u32,
            prior_question_versions: q.version - 1,
            distinct_prior_code_trees: prior_trees.iter().filter(|t| *t != &bundle.info.tree_sha256).count() as u32,
            prior_code_trees_in_session: prior_trees,
            same_question_text_other_sessions: ctx.store.note_text_run(&text_sha, &self.id),
        };
        let id = random_hex(12);
        let number = st.runs.len() as u32 + 1;
        st.runs.push(RunState {
            id: id.clone(),
            number,
            parent: spec.parent.clone(),
            question_version: q.version,
            model_id: m.id,
            tree: bundle.info.tree_sha256.clone(),
            commitment: bundle.info.commitment_sha256.clone(),
            messages: messages.clone(),
            status: "running",
            steps: 0,
            trace,
            trace_bytes: 0,
            trace_full: false,
            turns: None,
            full: None,
            certificate: None,
            verdict: None,
            outcome: None,
            decision_note: None,
            started_at_ms: now_ms(),
            finished_at_ms: None,
            decided_at_ms: None,
        });
        let msg = match &spec.message {
            Some((rec, _)) => format!(
                "The auditor sent a {}follow-up message; run {number} started.",
                if rec.blinded { "blinded " } else { "" }
            ),
            None => format!(
                "Run {number} started with {} / {}.",
                m.provider.as_str(),
                m.model
            ),
        };
        self.event(
            ctx,
            st,
            "run_started",
            msg,
            None,
            if spec.message.is_some() {
                Some(Role::Auditor)
            } else {
                None
            },
            spec.message.is_some(),
        );

        let question = QuestionRecord {
            version: q.version,
            text: q.text.clone(),
            text_sha256: text_sha,
            max_steps: q.max_steps,
            allow_fine_tuned: q.allow_fine_tuned,
            asked_at_ms: q.asked_at_ms,
            accepted_at_ms: q.decided_at_ms.unwrap_or(q.asked_at_ms),
            answer_format: q.answer_format.clone(),
        };
        let job = RunJob {
            session: self.clone(),
            ctx: ctx.clone(),
            run_id: id.clone(),
            number,
            parent: spec.parent,
            client,
            bundle,
            turns,
            question,
            affidavit,
            model_info,
            history,
            messages: messages.iter().map(|(r, _)| r.clone()).collect(),
            harness_prompt: crate::harnesses::agent_prompt(
                &q.text,
                &q.answer_format,
                previous_verdict
                    .as_ref()
                    .zip(messages.last().map(|(_, t)| t.as_str())),
            ),
            harness_job,
        };
        tokio::spawn(job.execute());
        Ok(id)
    }

    // ------------------------------------------------------------ views

    pub fn view(&self, ctx: &Ctx, role: Role, since: u64) -> Value {
        let st = lock(&self.st);
        let events: Vec<Event> = st
            .events
            .iter()
            .filter(|e| e.seqs[ri(role)] > since)
            .map(|e| Event {
                seq: e.seqs[ri(role)],
                ..e.clone()
            })
            .collect();
        let runs: Vec<Value> = st.runs.iter().map(|r| run_view(r, role, &st)).collect();
        json!({
            "session_id": self.id,
            "role": role,
            "created_at_ms": self.created_at_ms,
            "version": st.versions[ri(role)],
            "boot_id": ctx.info.boot_id,
            "auditor_joined": st.auditor_joined,
            "questions": st.questions,
            "code": st.code.as_ref().map(|b| match role {
                Role::Auditee => json!(b.info),
                Role::Auditor => json!({"commitment_sha256": b.info.commitment_sha256, "uploaded_at_ms": b.info.uploaded_at_ms}),
            }),
            "affidavit": st.affidavit.as_ref().map(|(tree, rec)| {
                let current = st.code.as_ref().is_some_and(|c| &c.info.tree_sha256 == tree);
                let mut a = json!({"record": rec, "current": current});
                if role == Role::Auditee {
                    a["tree_sha256"] = json!(tree);
                }
                a
            }),
            "models": st.models.iter().map(|m| m.public()).collect::<Vec<_>>(),
            "runs": runs,
            "disclosures": st.disclosures.iter().filter(|d| role == Role::Auditee || d.status == "published").map(|d| {
                let mut v = disclosure_view(d);
                if role == Role::Auditor {
                    v.as_object_mut().unwrap().remove("draft");
                }
                v
            }).collect::<Vec<_>>(),
            "events": events,
            "last_event_seq": st.event_counts[ri(role)],
            "notify": st.notify.get(&role).cloned().unwrap_or_default(),
            "email_available": ctx.email.is_some(),
            "status": status_line(&st, role),
            "next_actions": next_actions(&st, role, &self.id),
        })
    }

    pub fn trace(&self, role: Role, run_id: &str, after: usize) -> Result<Value> {
        ensure!(
            role == Role::Auditee,
            "only the auditee can see the agent's trace"
        );
        let st = lock(&self.st);
        let r = st
            .runs
            .iter()
            .find(|r| r.id == run_id)
            .ok_or_else(|| anyhow!("no such run"))?;
        Ok(
            json!({"run_id": r.id, "status": r.status, "next": r.trace.len(), "entries": &r.trace[after.min(r.trace.len())..]}),
        )
    }

    /// Draft a disclosure: read a file, or run a Python script over the code
    /// in the sandbox. Only the auditee sees the draft.
    pub async fn draft_disclosure(
        self: &Arc<Self>,
        ctx: &Arc<Ctx>,
        role: Role,
        v: &Value,
    ) -> Result<Value> {
        use base64::Engine as _;
        ensure!(role == Role::Auditee, "only the auditee discloses");
        // Reserve a place before any slow work, so concurrent requests can't
        // all pass the limit check.
        let (bundle, _reservation) = {
            let mut st = lock(&self.st);
            ensure!(
                st.disclosures.len() + st.disclosures_in_flight < MAX_DISCLOSURES,
                "this session has {MAX_DISCLOSURES} disclosures already"
            );
            ensure!(
                st.disclosures_in_flight < MAX_DISCLOSURES_IN_FLIGHT,
                "wait for the disclosures being prepared to finish"
            );
            let bundle = st
                .code
                .clone()
                .ok_or_else(|| anyhow!("upload code first"))?;
            st.disclosures_in_flight += 1;
            (bundle, DisclosureReservation(self.clone()))
        };
        let note = field(v, "note", MAX_NOTE_BYTES)?;
        ensure!(
            note.as_ref().map_or(0, |n| n.len()) <= 4000,
            "the note is over 4000 bytes"
        );
        let content = match v["kind"].as_str() {
            Some("file") => {
                let raw = v["path"].as_str().unwrap_or_default();
                let path = attest_core::tree::normalize_path(raw.trim())
                    .ok_or_else(|| anyhow!("bad path {raw:?}"))?;
                let e = bundle
                    .files
                    .get(&path)
                    .ok_or_else(|| anyhow!("no such file: {path}"))?;
                ensure!(
                    e.size <= MAX_DISCLOSED_FILE,
                    "{path} is over {} KiB; disclose a script's output instead",
                    MAX_DISCLOSED_FILE >> 10
                );
                let sha256 = hex::encode(e.digest);
                let bytes = bundle.read(&path).await?;
                let (text, b64) = match std::str::from_utf8(&bytes) {
                    Ok(t) => (Some(t.to_string()), None),
                    Err(_) => (
                        None,
                        Some(base64::engine::general_purpose::STANDARD.encode(&*bytes)),
                    ),
                };
                DisclosureContent::File {
                    path,
                    size: bytes.len() as u64,
                    sha256,
                    text,
                    base64: b64,
                }
            }
            Some("python") => {
                let code = v["code"].as_str().unwrap_or_default().to_string();
                ensure!(!code.trim().is_empty(), "code is empty");
                ensure!(
                    code.len() <= MAX_SCRIPT_BYTES,
                    "the script is over {MAX_SCRIPT_BYTES} bytes"
                );
                let sandbox = ctx.sandbox.get().cloned().ok_or_else(|| {
                    anyhow!("the python sandbox is still starting up; try again in a minute")
                })?;
                let _slot = ctx
                    .disclosure_slots
                    .acquire()
                    .await
                    .map_err(|_| anyhow!("shutting down"))?;
                let _pin = bundle.pin().await?;
                let opened = Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
                let out = sandbox
                    .run_python(bundle.clone(), &code, opened.clone())
                    .await;
                let files_opened = opened
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|(k, d)| (k.clone(), hex::encode(d)))
                    .collect();
                DisclosureContent::Python {
                    code_sha256: sha256_hex(code.as_bytes()),
                    code,
                    stdout: out.stdout,
                    stderr: out.stderr,
                    exit_code: out.exit_code,
                    timed_out: out.timed_out,
                    error: out.error,
                    files_opened,
                }
            }
            _ => bail!("kind must be \"file\" or \"python\""),
        };
        let mut st = lock(&self.st);
        ensure!(
            st.code.as_ref().is_some_and(|c| Arc::ptr_eq(c, &bundle)),
            "the code was replaced while the disclosure was being prepared; try again"
        );
        let held: usize = st
            .disclosures
            .iter()
            .map(|d| disclosure_bytes(&d.body.content))
            .sum();
        ensure!(
            held + disclosure_bytes(&content) <= MAX_DISCLOSURE_BYTES,
            "this session's disclosures would hold more than {} MiB; discard some drafts first",
            MAX_DISCLOSURE_BYTES >> 20
        );
        let body = DisclosureBody {
            schema: "attest/disclosure-body/v1".into(),
            session_id: self.id.clone(),
            boot_id: ctx.info.boot_id.clone(),
            number: 0,
            code_commitment_sha256: bundle.info.commitment_sha256.clone(),
            note,
            created_at_ms: now_ms(),
            published_at_ms: 0,
            content,
        };
        let draft = st.disclosures.len() as u32 + 1;
        let out = disclosure_view(&DisclosureState {
            draft,
            body: body.clone(),
            status: "draft",
            signed: None,
        });
        st.disclosures.push(DisclosureState {
            draft,
            body,
            status: "draft",
            signed: None,
        });
        self.changed_for(&mut st, Role::Auditee);
        Ok(out)
    }

    /// Publish (sign and show the auditor) or discard a draft.
    pub fn decide_disclosure(
        self: &Arc<Self>,
        ctx: &Arc<Ctx>,
        role: Role,
        number: u32,
        v: &Value,
    ) -> Result<Value> {
        ensure!(role == Role::Auditee, "only the auditee discloses");
        let publish = v["publish"]
            .as_bool()
            .ok_or_else(|| anyhow!("publish (true or false) is required"))?;
        let mut st = lock(&self.st);
        let current = st.code.as_ref().map(|c| c.info.commitment_sha256.clone());
        let d = st
            .disclosures
            .iter_mut()
            .find(|d| d.draft == number)
            .ok_or_else(|| anyhow!("no such disclosure"))?;
        ensure!(
            d.status == "draft",
            "disclosure {number} is already {}",
            d.status
        );
        if !publish {
            d.status = "discarded";
            // Nothing will be done with a discarded draft's content.
            match &mut d.body.content {
                DisclosureContent::File { text, base64, .. } => {
                    *text = None;
                    *base64 = None;
                }
                DisclosureContent::Python { code, stdout, stderr, files_opened, .. } => {
                    code.clear();
                    stdout.clear();
                    stderr.clear();
                    files_opened.clear();
                }
            }
            self.changed_for(&mut st, Role::Auditee);
            return Ok(json!({"number": number, "status": "discarded"}));
        }
        ensure!(
            current.as_deref() == Some(d.body.code_commitment_sha256.as_str()),
            "the code changed since this draft was made; draft it again"
        );
        let _ = d;
        let published = st
            .disclosures
            .iter()
            .filter(|d| d.status == "published")
            .count() as u32;
        let d = st
            .disclosures
            .iter_mut()
            .find(|d| d.draft == number)
            .unwrap();
        d.body.number = published + 1;
        let number = d.body.number;
        d.body.published_at_ms = now_ms();
        let signed = sign::sign(&ctx.signing, DOMAIN_DISCLOSURE, &d.body)?;
        d.signed = Some(Disclosure {
            enclave_info_json: ctx.info_json.clone(),
            boot_document_b64: ctx.boot_doc_b64.clone(),
            signed,
        });
        d.status = "published";
        // No path or content in the text: it can go out by email.
        let what = match &d.body.content {
            DisclosureContent::File { .. } => "a file",
            DisclosureContent::Python { .. } => "a script's output",
        };
        let out = disclosure_view(d);
        self.event(
            ctx,
            &mut st,
            "disclosure_published",
            format!("The auditee disclosed {what} (disclosure {number})."),
            None,
            Some(role),
            true,
        );
        Ok(out)
    }

    pub fn disclosure(&self, role: Role, number: u32) -> Result<Disclosure> {
        let st = lock(&self.st);
        let d = st
            .disclosures
            .iter()
            .find(|d| d.body.number == number)
            .ok_or_else(|| anyhow!("no such disclosure"))?;
        if role == Role::Auditor {
            ensure!(d.status == "published", "no such disclosure");
        }
        d.signed
            .clone()
            .ok_or_else(|| anyhow!("disclosure {number} is a draft; publish it first"))
    }

    pub fn certificate(&self, ctx: &Ctx, role: Role, run_id: &str) -> Result<Certificate> {
        let st = lock(&self.st);
        let r = st
            .runs
            .iter()
            .find(|r| r.id == run_id)
            .ok_or_else(|| anyhow!("no such run"))?;
        if role == Role::Auditor {
            ensure!(
                r.status == "released",
                "the auditee has not released this run"
            );
            return r
                .certificate
                .clone()
                .ok_or_else(|| anyhow!("run {} has no certificate", r.number));
        }
        // The auditee gets what was released, or before that (or after a
        // decline) a certificate of everything, theirs to keep or share.
        if let Some(c) = &r.certificate {
            return Ok(c.clone());
        }
        let full = r
            .full
            .as_ref()
            .ok_or_else(|| anyhow!("run {} has not finished", r.number))?;
        sign_certificate(ctx, full)
    }
}

struct RunSpec {
    question_version: u32,
    model_id: u32,
    parent: Option<String>,
    message: Option<(MessageRecord, String)>,
}

struct RunJob {
    session: Arc<Session>,
    ctx: Arc<Ctx>,
    run_id: String,
    number: u32,
    parent: Option<String>,
    client: Client,
    bundle: Arc<Bundle>,
    turns: Vec<Turn>,
    question: QuestionRecord,
    affidavit: AffidavitRecord,
    model_info: ModelInfo,
    history: History,
    messages: Vec<MessageRecord>,
    /// For jailed harnesses: (provider, model, key), and the prompt.
    harness_job: Option<(
        crate::harnesses::Agent,
        llm::Target,
        String,
        String,
        llm::Routing,
    )>,
    harness_prompt: String,
}

impl RunJob {
    async fn execute(self) {
        let ctx = self.ctx.clone();
        let _permit = ctx.slots.acquire().await;
        let started_at_ms = now_ms();
        let session = self.session.clone();
        let run_id = self.run_id.clone();
        let progress: Arc<dyn Fn(Vec<Value>) + Send + Sync> =
            Arc::new(move |entries: Vec<Value>| {
                let mut st = lock(&session.st);
                if let Some(r) = st.runs.iter_mut().find(|r| r.id == run_id) {
                    r.steps += entries
                        .iter()
                        .filter(|e| e["type"] == "assistant" || e["type"] == "model_exchange")
                        .count() as u32;
                    if r.trace_full {
                        return;
                    }
                    let size: usize = entries.iter().map(|e| e.to_string().len()).sum();
                    use std::sync::atomic::Ordering::Relaxed;
                    let total = TRACE_BYTES.load(Relaxed);
                    if r.trace_bytes + size > MAX_TRACE_BYTES_PER_RUN
                        || total + size > MAX_TRACE_BYTES_TOTAL
                    {
                        r.trace_full = true;
                        r.trace.push(json!({"type": "error", "content": "the trace reached its size limit; later steps aren't recorded (the run continues)"}));
                        return;
                    }
                    r.trace_bytes += size;
                    TRACE_BYTES.fetch_add(size, Relaxed);
                    r.trace.extend(entries);
                }
                // No wake-up here: the ticker below wakes the auditee on a
                // fixed schedule, so the timing of their trace fetches (which
                // the parent sees) doesn't follow what the agent does.
            });
        // Aborted however this function ends, so it can't keep the session
        // alive after a failed run.
        let ticker = AbortOnDrop({
            let session = self.session.clone();
            tokio::spawn(async move {
                let mut t = tokio::time::interval(Duration::from_secs(5));
                loop {
                    t.tick().await;
                    let mut st = lock(&session.st);
                    session.changed_for(&mut st, Role::Auditee);
                }
            })
        });
        // Email the auditee at the run's time limit, whether or not it has
        // finished: a completion-triggered email would carry its timing.
        {
            let (session, ctx, n) = (self.session.clone(), self.ctx.clone(), self.number);
            let limit = run_time_limit(self.question.max_steps);
            tokio::spawn(async move {
                tokio::time::sleep(limit).await;
                let decided =
                    lock(&session.st).runs.iter().any(|r| {
                        r.number == n && (r.status == "released" || r.status == "declined")
                    });
                if decided {
                    return;
                }
                session.email(&ctx, Role::Auditee, format!("Run {n} has had its full time ({} min). Once it has finished, review it and decide whether to release it.", limit.as_secs() / 60));
            });
        }
        // Loading and the agent together get the run's time limit (plus a
        // margin for the jail's own shutdown), and a panic anywhere in them
        // ends the run as failed instead of leaving it "running" forever.
        let deadline = run_time_limit(self.question.max_steps) + Duration::from_secs(120);
        let work = std::panic::AssertUnwindSafe(self.agent(progress.clone()));
        let out = match tokio::time::timeout(deadline, futures_util::FutureExt::catch_unwind(work)).await {
            Ok(Ok(out)) => out,
            Ok(Err(_)) => failed_output("the run failed inside the enclave (an internal error)"),
            Err(_) => failed_output(&format!(
                "the run did not finish within its {} minutes",
                deadline.as_secs() / 60
            )),
        };
        self.finish(out, started_at_ms, ticker);
    }

    /// Load the code and run the agent.
    async fn agent(&self, progress: Arc<dyn Fn(Vec<Value>) + Send + Sync>) -> run::AgentOutput {
        // Load all the code into enclave memory first; from here on the
        // host sees no reads that depend on what the agent does.
        let pin = self.bundle.pin().await;
        match (&pin, &self.harness_job) {
            (Err(e), _) => run::AgentOutput {
                turns: vec![],
                verdict: None,
                outcome: Outcome::Error {
                    message: format!("loading the code: {e:#}"),
                },
                activity: Default::default(),
                files_read: Default::default(),
                response_models: vec![],
                upstream_providers: vec![],
                key_owner: None,
            },
            (Ok(_), Some((agent, target, model, key, routing))) => {
                let timeout = run_time_limit(self.question.max_steps);
                crate::harnesses::run_agent(
                    *agent,
                    self.ctx.net.clone(),
                    &self.run_id,
                    &self.bundle,
                    target.clone(),
                    model,
                    key,
                    routing.clone(),
                    self.harness_prompt.clone(),
                    &self.question.answer_format,
                    timeout,
                    progress.clone(),
                )
                .await
            }
            (Ok(_), None) => {
                let sandbox = self.ctx.sandbox.get().cloned();
                run::agent_loop(
                    &self.client,
                    &self.bundle,
                    sandbox,
                    self.turns.clone(),
                    self.question.max_steps,
                    &self.question.answer_format,
                    &*progress,
                )
                .await
            }
        }
    }

    /// Record the run's result and start whatever is queued next.
    fn finish(self, out: run::AgentOutput, started_at_ms: u64, ticker: AbortOnDrop) {
        let mut model = self.model_info.clone();
        model.response_models = out.response_models.clone();
        model.upstream_providers = out.upstream_providers.clone();
        model.key_owner = out.key_owner.clone();
        let manifest = Manifest {
            schema: "attest/manifest/v2".into(),
            session_id: self.session.id.clone(),
            run_id: self.run_id.clone(),
            run_number: self.number,
            parent_run_id: self.parent.clone(),
            boot_id: self.ctx.info.boot_id.clone(),
            started_at_ms,
            finished_at_ms: now_ms(),
            question: self.question.clone(),
            auditor_messages: self.messages.clone(),
            affidavit: self.affidavit.clone(),
            code: self.bundle.info.clone(),
            model,
            harness: self.ctx.info.harness.clone(),
            activity: out.activity.clone(),
            instruction_scan: InstructionScan {
                patterns_version: scan::PATTERNS_VERSION.into(),
                whole_bundle: self.bundle.scan_all(),
                files_read: self.bundle.scan_paths(out.files_read.keys()),
            },
            history: self.history.clone(),
            outcome: out.outcome.clone(),
            detail: "full".into(),
        };
        let body = CertificateBody {
            manifest,
            verdict: out.verdict.clone(),
        };

        let mut st = lock(&self.session.st);
        let Some(r) = st.runs.iter_mut().find(|r| r.id == self.run_id) else {
            return;
        };
        r.status = "awaiting_release";
        r.finished_at_ms = Some(now_ms());
        r.turns = Some(out.turns);
        r.verdict = out.verdict.clone();
        r.outcome = Some(out.outcome.clone());
        r.full = Some(body);
        let n = self.number;
        // The outcome (verdict, step limit, failure) is model-controlled, so
        // it stays out of the event text, which can go out by email.
        self.session.event(
            &self.ctx,
            &mut st,
            "run_finished",
            format!("Run {n} finished. Review it and decide whether to release it."),
            Some(Role::Auditee),
            None,
            false,
        );
        drop(ticker);

        let s = self.session.clone();
        drop(st);
        let mut st = lock(&s.st);
        s.maybe_start(&self.ctx, &mut st);
    }
}

/// How long a run may take; also when the auditee is emailed about it.
/// Aborts a background task when dropped.
pub struct AbortOnDrop(pub tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn failed_output(message: &str) -> run::AgentOutput {
    run::AgentOutput {
        turns: vec![],
        verdict: None,
        outcome: Outcome::Error {
            message: message.into(),
        },
        activity: Default::default(),
        files_read: Default::default(),
        response_models: vec![],
        upstream_providers: vec![],
        key_owner: None,
    }
}

fn run_time_limit(max_steps: u32) -> Duration {
    Duration::from_secs((max_steps as u64 * 20).clamp(300, 1800))
}

/// With a strict answer format, the result should carry little beyond the
/// answer. Activity numbers are steered by the model, so they are rounded up
/// to powers of two; per-file detail is dropped; times are rounded to the hour.
fn minimize_for_strict_format(m: &mut Manifest) {
    let p2 = |n: u64| if n == 0 { 0 } else { n.checked_next_power_of_two().unwrap_or(u64::MAX) };
    let a = &mut m.activity;
    *a = Activity {
        llm_calls: p2(a.llm_calls as u64) as u32,
        tool_calls: p2(a.tool_calls as u64) as u32,
        input_tokens: p2(a.input_tokens),
        output_tokens: p2(a.output_tokens),
        files_read: p2(a.files_read),
        ..Default::default()
    };
    m.instruction_scan.files_read = ScanCounts::default();
    let hour = 3_600_000;
    m.started_at_ms -= m.started_at_ms % hour;
    m.finished_at_ms -= m.finished_at_ms % hour;
    if let Outcome::Error { message } = &mut m.outcome {
        *message = "details withheld (strict answer format)".into();
    }
}

/// What the auditor gets. By default only the verdict: everything else the
/// code or the model could have shaped (run times, the code's tree hash and
/// size, activity and instruction-scan counts, earlier code trees, error
/// text) is left out. With `details` the auditee releases the full record,
/// coarsened as before for strict answer formats.
fn public_body(full: &CertificateBody, details: bool, strict: bool) -> CertificateBody {
    let mut b = full.clone();
    let m = &mut b.manifest;
    if details {
        m.detail = "full".into();
        if strict {
            minimize_for_strict_format(m);
        }
        return b;
    }
    m.detail = "verdict_only".into();
    m.started_at_ms = 0;
    m.finished_at_ms = 0;
    m.code = CodeInfo {
        tree_sha256: String::new(),
        file_count: 0,
        text_file_count: 0,
        total_bytes: 0,
        uploaded_at_ms: 0,
        commitment_sha256: m.code.commitment_sha256.clone(),
        commitment_salt: String::new(),
    };
    m.activity = Activity::default();
    m.instruction_scan = InstructionScan::default();
    m.history.prior_code_trees_in_session.clear();
    m.history.same_question_text_other_sessions = 0;
    if let Outcome::Error { message } = &mut m.outcome {
        *message = "details withheld".into();
    }
    b
}

fn sign_certificate(ctx: &Ctx, body: &CertificateBody) -> Result<Certificate> {
    Ok(Certificate {
        enclave_info_json: ctx.info_json.clone(),
        boot_document_b64: ctx.boot_doc_b64.clone(),
        signed: sign::sign(&ctx.signing, DOMAIN_CERTIFICATE, body)?,
    })
}

/// Whether the auditor may see that a run finished (as opposed to its
/// result, which is always gated on release). With strict formats they may
/// not: how long a run takes is model-controlled and would be a side channel.
/// Whether `role` should treat a run as still going. The auditor can't
/// tell a finished-but-undecided run from a running one, through any API.
fn busy_for(st: &State, role: Role) -> bool {
    st.runs
        .iter()
        .any(|r| r.status == "running" || (role == Role::Auditor && r.status == "awaiting_release"))
}

fn auditor_sees_finish(_st: &State, _r: &RunState) -> bool {
    // Never: run duration is model-controlled. The auditor learns of a run's
    // end only from the auditee's release or decline.
    false
}

fn disclosure_view(d: &DisclosureState) -> Value {
    json!({"draft": d.draft, "number": d.body.number, "status": d.status, "body": d.body})
}

fn run_view(r: &RunState, role: Role, st: &State) -> Value {
    let model = st.models.iter().find(|m| m.id == r.model_id);
    let mut v = json!({
        "id": r.id, "number": r.number, "parent_run_id": r.parent, "question_version": r.question_version,
        "model": model.map(|m| json!({"id": m.id, "provider": m.provider, "model": m.model, "proposed_by": m.by})),
        "code_commitment_sha256": r.commitment, "status": r.status,
        "started_at_ms": r.started_at_ms, "finished_at_ms": r.finished_at_ms, "decided_at_ms": r.decided_at_ms,
        "decision_note": r.decision_note,
    });
    if role == Role::Auditor {
        // Run duration is model-controlled: the auditor never sees when a
        // run finished, only the auditee's decision.
        v["finished_at_ms"] = Value::Null;
        if r.status == "awaiting_release" && !auditor_sees_finish(st, r) {
            v["status"] = json!("running");
        }
    }
    if role == Role::Auditee {
        v["code_tree_sha256"] = json!(r.tree);
        v["verdict"] = json!(r.verdict);
        v["outcome"] = json!(r.outcome);
        v["has_certificate"] = json!(r.full.is_some());
        if let Some(body) = &r.full {
            v["flags"] = json!(attest_core::verify::manifest_warnings(&body.manifest));
            v["manifest"] = json!(body.manifest);
        }
        if let Some(c) = &r.certificate {
            if let Ok(body) = serde_json::from_str::<CertificateBody>(&c.signed.body) {
                v["released_detail"] = json!(body.manifest.detail);
            }
        }
    } else if r.status == "released" {
        // Everything the auditor sees about the result comes from the
        // signed certificate the auditee released, and nothing else.
        v["has_certificate"] = json!(r.certificate.is_some());
        if let Some(c) = &r.certificate {
            if let Ok(body) = serde_json::from_str::<CertificateBody>(&c.signed.body) {
                v["verdict"] = json!(body.verdict);
                v["outcome"] = json!(body.manifest.outcome);
                v["flags"] = json!(attest_core::verify::manifest_warnings(&body.manifest));
                if !body.manifest.verdict_only() {
                    v["code_tree_sha256"] = json!(body.manifest.code.tree_sha256);
                }
                v["manifest"] = json!(body.manifest);
            }
        }
    }
    match role {
        Role::Auditee => {
            v["steps"] = json!(r.steps);
            v["trace_length"] = json!(r.trace.len());
            v["messages"] = json!(r.messages.iter().map(|(m, _)| m).collect::<Vec<_>>());
        }
        Role::Auditor => {
            v["messages"] = json!(r
                .messages
                .iter()
                .map(|(m, t)| json!({"sent_at_ms": m.sent_at_ms, "blinded": m.blinded, "text": t}))
                .collect::<Vec<_>>());
        }
    }
    v
}

pub fn affidavit_statement(
    org: &str,
    commitment: &str,
    repo_url: Option<&str>,
    git_commit: Option<&str>,
) -> String {
    format!(
        "On behalf of {org}, I affirm that the code uploaded to this session (code commitment {commitment}, opened in each released certificate) is a complete and unmodified copy of {} at commit {}, \
         which is the source currently used in production for the systems the question concerns, and that no content in it was added, \
         modified, or arranged with the intent of influencing the outcome of this or any automated audit.",
        repo_url.unwrap_or("(repository not named)"),
        git_commit.unwrap_or("(commit not named)"),
    )
}

fn status_line(st: &State, role: Role) -> String {
    let q = st.questions.last();
    if busy_for(st, role)
        && (role == Role::Auditor || st.runs.iter().any(|r| r.status == "running"))
    {
        return match role {
            Role::Auditee => "The agent is running. You can watch it.".into(),
            Role::Auditor => {
                "The agent is running. You'll see the result if the auditee releases it.".into()
            }
        };
    }
    if st.runs.iter().any(|r| r.status == "awaiting_release") {
        return match role {
            Role::Auditee => "A result is waiting for your decision.".into(),
            Role::Auditor => "The agent finished. Waiting for the auditee to decide whether to release the result.".into(),
        };
    }
    match q.map(|q| q.status) {
        None => return "Waiting for the auditor to ask a question.".into(),
        Some("proposed") => return "Waiting for the auditee to accept the question.".into(),
        Some("rejected") => {
            return "The auditee rejected the question. Waiting for the auditor to revise it."
                .into()
        }
        _ => {}
    }
    let mut missing = Vec::new();
    match (&st.code, &st.affidavit) {
        (None, _) => missing.push("the auditee to upload code"),
        (Some(c), Some((t, _))) if t == &c.info.tree_sha256 => {}
        _ => missing.push("the auditee to confirm the affidavit"),
    }
    if !st.models.iter().any(|m| m.status == "approved") {
        missing.push(if st.models.iter().any(|m| m.status == "pending") {
            "the auditee to approve a model"
        } else {
            "a model and API key"
        });
    }
    if missing.is_empty() {
        if let (Some(q), Some(m)) = (q, st.models.iter().rev().find(|m| m.status == "approved")) {
            if llm::is_fine_tuned(m.provider, &m.model) && !q.allow_fine_tuned {
                return "The approved model is a fine-tune, which the question does not allow. Choose another model.".into();
            }
        }
        if st.runs.is_empty() {
            return "Starting.".into();
        }
        return "Done. The auditor can send a follow-up or revise the question.".into();
    }
    format!("Waiting for {}.", missing.join(", "))
}

fn next_actions(st: &State, role: Role, sid: &str) -> Vec<Value> {
    let a = |action: &str, method: &str, path: String, description: &str| json!({"action": action, "method": method, "path": path, "description": description});
    let base = format!("/api/sessions/{sid}");
    let mut out = Vec::new();
    let q = st.questions.last();
    let running = busy_for(st, role);
    match role {
        Role::Auditor => {
            let can_ask = match q {
                None => true,
                Some(q) => q.status == "rejected" || q.status == "accepted",
            };
            if can_ask {
                out.push(a(
                    "propose_question",
                    "POST",
                    format!("{base}/question"),
                    if q.is_none() {
                        "Ask your question."
                    } else {
                        "Revise the question (the auditee must accept it again)."
                    },
                ));
            }
            if !st
                .models
                .iter()
                .any(|m| m.status == "approved" || (m.status == "pending" && m.by == Role::Auditor))
            {
                out.push(a("propose_model", "POST", format!("{base}/models"), "Optionally propose a provider, model and your own API key (the auditee must approve)."));
            }
            for r in st
                .runs
                .iter()
                .filter(|r| r.status == "released" || r.status == "declined")
            {
                if !running {
                    out.push(a(
                        "send_followup",
                        "POST",
                        format!("{base}/runs/{}/followup", r.id),
                        "Send the agent a follow-up message (optionally blinded from the auditee).",
                    ));
                }
                if r.status == "released" {
                    out.push(a(
                        "get_certificate",
                        "GET",
                        format!("{base}/runs/{}/certificate", r.id),
                        "Download the signed certificate.",
                    ));
                }
            }
        }
        Role::Auditee => {
            if let Some(q) = q.filter(|q| q.status == "proposed") {
                out.push(a(
                    "decide_question",
                    "POST",
                    format!("{base}/question/decision"),
                    &format!("Accept or reject question version {}.", q.version),
                ));
            }
            if st.code.is_none() {
                out.push(a(
                    "upload_code",
                    "PUT",
                    format!("{base}/code"),
                    "Upload your code as a tar archive.",
                ));
            } else if !st
                .affidavit
                .as_ref()
                .is_some_and(|(t, _)| Some(t) == st.code.as_ref().map(|c| &c.info.tree_sha256))
            {
                out.push(a(
                    "confirm_affidavit",
                    "POST",
                    format!("{base}/affidavit"),
                    "Confirm the affidavit for the uploaded code.",
                ));
            }
            for m in st.models.iter().filter(|m| m.status == "pending") {
                out.push(a(
                    "decide_model",
                    "POST",
                    format!("{base}/models/{}/decision", m.id),
                    &format!(
                        "Approve or reject {} / {} proposed by the auditor.",
                        m.provider.as_str(),
                        m.model
                    ),
                ));
            }
            if !st
                .models
                .iter()
                .any(|m| m.status == "approved" || m.status == "pending")
            {
                out.push(a(
                    "propose_model",
                    "POST",
                    format!("{base}/models"),
                    "Choose a provider, model and API key.",
                ));
            }
            for r in st.runs.iter().filter(|r| r.status == "awaiting_release") {
                out.push(a(
                    "decide_release",
                    "POST",
                    format!("{base}/runs/{}/release", r.id),
                    &format!(
                        "Release run {}'s result to the auditor, or decline.",
                        r.number
                    ),
                ));
            }
            for r in st.runs.iter().filter(|r| r.status == "running") {
                out.push(a(
                    "watch_trace",
                    "GET",
                    format!("{base}/runs/{}/trace?after=0", r.id),
                    &format!("Watch run {} live.", r.number),
                ));
            }
        }
    }
    out
}

/// Wait until the session changes past `version`, or the timeout.
pub async fn wait_for_change(session: &Session, role: Role, version: u64, timeout: Duration) {
    let mut rx = session.subscribe(role);
    let _ = tokio::time::timeout(timeout, rx.wait_for(|v| *v > version)).await;
}
