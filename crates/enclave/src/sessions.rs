//! Sessions: two parties, one question, the auditee's code, and agent runs.
//!
//! A party is whoever holds the session's auditee or auditor link. State
//! lives in enclave memory, and is also written, sealed, to the parent's
//! store (see persist.rs) a couple of seconds after each change, so an
//! enclave of the same image can take the sessions over (handoff.rs).
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
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;

mod durable;
pub use durable::write_loop;

pub const UPLOAD_ALLOWANCE: usize = SESSION_ALLOWANCE;
pub const SESSION_TTL_MS: u64 = 30 * 24 * 3600 * 1000;
const MAX_QUESTION_CHARS: usize = 20_000;
const MAX_MESSAGE_CHARS: usize = 20_000;
/// Events kept per session (the activity feed).
const MAX_EVENTS: usize = 500;

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
    /// Sealed durable state, under this lineage's master key.
    pub persist: Arc<crate::persist::Persist>,
    pub lineage: crate::persist::Lineage,
    /// Set once this enclave handed its sessions to a successor: it serves
    /// no session requests after that.
    /// Standbys following this enclave's writes (replica.rs).
    pub repl: crate::replica::Replication,
    /// True while this enclave is a standby: it serves no sessions.
    pub standby: AtomicBool,
    pub moved: AtomicBool,
    /// Held (shared) by every request that changes session state, and
    /// exclusively by a handoff: so a handoff waits for changes already
    /// under way, and none happen during or after it.
    pub owner: tokio::sync::RwLock<()>,
}

#[derive(Default)]
pub struct Store {
    sessions: Mutex<HashMap<String, Arc<Session>>>,
    /// question text sha256 -> sessions that ran it
    text_index: Mutex<HashMap<String, HashSet<String>>>,
    last_sweep: std::sync::atomic::AtomicU64,
    /// Durable state, for deleting a removed session's records.
    pub persist: std::sync::OnceLock<Arc<crate::persist::Persist>>,
    /// One round of state writes at a time.
    persisting: tokio::sync::Mutex<()>,
    /// Sessions a predecessor handed over that couldn't be read back yet
    /// (the parent withheld or damaged a record), with the head hash they
    /// must match. Retried in the background, and passed on in any later
    /// handoff, so the set of sessions never quietly shrinks.
    pub(crate) pending: Mutex<Vec<(String, String)>>,
    /// The session ids last written to the lineage's index (durable.rs).
    index_written: Mutex<Option<Vec<String>>>,
}

pub struct Session {
    pub id: String,
    pub created_at_ms: u64,
    token_hashes: [String; 2],
    /// The role of whoever started the session. Their page shows the other
    /// party's link, derived from their own token (`invite_token`).
    pub creator: Option<Role>,
    st: Mutex<State>,
    /// Bumped on every change, so long-polls can wait for one.
    /// Change counters, one per role: [auditee, auditor]. Private changes
    /// (the live trace, auditee-only events) never touch the auditor's,
    /// so the auditor can't observe the run through them.
    tx: [watch::Sender<u64>; 2],
    /// Changed since its state was last written.
    dirty: AtomicBool,
    /// The last state written: snapshot generation and the head record's hash.
    written: Mutex<(u64, Option<String>)>,
    /// This session's share of budget::STATES.
    measured: std::sync::atomic::AtomicUsize,
    /// Tool calls waiting for the auditee's decision (approvals.rs).
    pub approvals: Arc<crate::approvals::Queue>,
}

#[derive(Default)]
struct State {
    /// Set when the session is swept away; nothing new starts after that.
    expired: bool,
    versions: [u64; 2],
    auditor_joined: bool,
    /// The other party's link is a one-time invite (`join`): their working
    /// token is made when they open it, so the creator never holds it.
    /// False only for sessions from before invites, whose invitee used the
    /// derived token directly.
    invites: bool,
    /// When the invite was used, and the hash of the token it gave out.
    joined: Option<Joined>,
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
    /// Services connected for the agent (connections.rs).
    connections: Vec<crate::connections::Connection>,
    /// The auditee approves each tool call of runs started while this is on.
    tool_approval: bool,
    /// Retired (the auditor never sees the agent's work); kept so stored
    /// state still loads.
    #[allow(dead_code)]
    auditor_watch: String,
}

/// A raw model exchange (Anthropic or OpenAI; JSON or SSE) as a readable
/// turn: the results of earlier tool calls the request carried, then what
/// the model said and which tools it called with which inputs.
fn exchange_turn(e: &Value) -> Value {
    let mut results = Vec::new();
    let text_of = |c: &Value| -> String {
        match c {
            Value::String(s) => s.clone(),
            Value::Array(a) => a.iter().filter_map(|b| b["text"].as_str().or(b["output"].as_str())).collect::<Vec<_>>().join("\n"),
            _ => String::new(),
        }
    };
    for it in e["request"]["new"].as_array().into_iter().flatten() {
        // Anthropic: a user message with tool_result blocks.
        for b in it["content"].as_array().into_iter().flatten() {
            if b["type"] == "tool_result" {
                results.push(json!({"id": b["tool_use_id"], "content": text_of(&b["content"]), "error": b["is_error"].as_bool().unwrap_or(false)}));
            }
        }
        // OpenAI Responses and Chat Completions.
        let t = it["type"].as_str().unwrap_or("");
        if t.ends_with("_call_output") {
            results.push(json!({"id": it["call_id"], "content": text_of(&it["output"]), "error": false}));
        } else if it["role"] == "tool" {
            results.push(json!({"id": it["tool_call_id"], "content": text_of(&it["content"]), "error": false}));
        }
    }
    let raw = e["response"].as_str().unwrap_or("");
    let mut text: Vec<String> = Vec::new();
    let mut calls: Vec<Value> = Vec::new();
    // Blocks by index while streaming: (kind, id, name, accumulated).
    let mut blocks: std::collections::BTreeMap<i64, (String, Value, Value, String)> = Default::default();
    let mut chat_calls: std::collections::BTreeMap<i64, (Value, String, String)> = Default::default();
    let mut chat_text = String::new();
    let parse_args = |s: &str| serde_json::from_str::<Value>(s).unwrap_or_else(|_| if s.is_empty() { json!({}) } else { json!(s) });
    let whole = |v: &Value, text: &mut Vec<String>, calls: &mut Vec<Value>| {
        // A complete response (non-streaming), or a finished Responses item.
        for b in v["content"].as_array().into_iter().flatten() {
            match b["type"].as_str() {
                Some("text") => text.push(b["text"].as_str().unwrap_or("").into()),
                Some("tool_use") | Some("server_tool_use") => calls.push(json!({"id": b["id"], "name": b["name"], "input": b["input"]})),
                _ => {}
            }
        }
        for it in v["output"].as_array().into_iter().flatten() {
            item(it, text, calls);
        }
        for c in v["choices"].as_array().into_iter().flatten() {
            if let Some(t) = c["message"]["content"].as_str() {
                if !t.is_empty() { text.push(t.into()); }
            }
            for tc in c["message"]["tool_calls"].as_array().into_iter().flatten() {
                calls.push(json!({"id": tc["id"], "name": tc["function"]["name"], "input": parse_args(tc["function"]["arguments"].as_str().unwrap_or(""))}));
            }
        }
    };
    fn item(it: &Value, text: &mut Vec<String>, calls: &mut Vec<Value>) {
        let parse = |s: &str| serde_json::from_str::<Value>(s).unwrap_or_else(|_| json!(s));
        match it["type"].as_str() {
            Some("message") => {
                for c in it["content"].as_array().into_iter().flatten() {
                    if let Some(t) = c["text"].as_str() { text.push(t.into()); }
                }
            }
            Some("function_call") => calls.push(json!({"id": it["call_id"], "name": it["name"], "input": parse(it["arguments"].as_str().unwrap_or(""))})),
            Some("custom_tool_call") => calls.push(json!({"id": it["call_id"], "name": it["name"], "input": it["input"]})),
            Some("local_shell_call") => calls.push(json!({"id": it["call_id"], "name": "shell", "input": it["action"]})),
            _ => {}
        }
    }
    if let Ok(v) = serde_json::from_str::<Value>(raw) {
        whole(&v, &mut text, &mut calls);
    } else {
        for line in raw.lines() {
            let Some(d) = line.strip_prefix("data:") else { continue };
            let Ok(v) = serde_json::from_str::<Value>(d.trim()) else { continue };
            let i = v["index"].as_i64().unwrap_or(0);
            match v["type"].as_str() {
                Some("content_block_start") => {
                    let b = &v["content_block"];
                    let init = b["text"].as_str().unwrap_or("").to_string();
                    blocks.insert(i, (b["type"].as_str().unwrap_or("").into(), b["id"].clone(), b["name"].clone(), init));
                }
                Some("content_block_delta") => {
                    if let Some(b) = blocks.get_mut(&i) {
                        let d = &v["delta"];
                        b.3.push_str(d["text"].as_str().or(d["partial_json"].as_str()).unwrap_or(""));
                    }
                }
                Some("response.output_item.done") => item(&v["item"], &mut text, &mut calls),
                _ => {
                    // Chat Completions chunks.
                    for c in v["choices"].as_array().into_iter().flatten() {
                        chat_text.push_str(c["delta"]["content"].as_str().unwrap_or(""));
                        for tc in c["delta"]["tool_calls"].as_array().into_iter().flatten() {
                            let k = tc["index"].as_i64().unwrap_or(0);
                            let ent = chat_calls.entry(k).or_insert((Value::Null, String::new(), String::new()));
                            if !tc["id"].is_null() { ent.0 = tc["id"].clone(); }
                            ent.1.push_str(tc["function"]["name"].as_str().unwrap_or(""));
                            ent.2.push_str(tc["function"]["arguments"].as_str().unwrap_or(""));
                        }
                    }
                }
            }
        }
        for (_, (kind, id, name, acc)) in blocks {
            match kind.as_str() {
                "text" if !acc.is_empty() => text.push(acc),
                "tool_use" | "server_tool_use" => calls.push(json!({"id": id, "name": name, "input": parse_args(&acc)})),
                _ => {}
            }
        }
        if !chat_text.is_empty() { text.push(chat_text); }
        for (_, (id, name, args)) in chat_calls {
            calls.push(json!({"id": id, "name": name, "input": parse_args(&args)}));
        }
    }
    json!({"results": results, "text": text, "calls": calls})
}

/// A status: one of a fixed set of strings. (An alias, so serde doesn't
/// treat it as a borrowed string when reading stored state.)
type Status = &'static str;

/// Statuses are fixed strings in memory; stored state names them.
mod status {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};
    const KNOWN: &[&str] = &[
        "proposed", "accepted", "rejected", "superseded", "pending", "approved", "running",
        "awaiting_release", "released", "declined", "draft", "published", "discarded",
    ];
    pub fn serialize<S: Serializer>(s: &&'static str, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<&'static str, D::Error> {
        let s = String::deserialize(d)?;
        KNOWN
            .iter()
            .find(|k| **k == s)
            .copied()
            .ok_or_else(|| D::Error::custom(format!("unknown status {s:?}")))
    }
}

/// A disclosure starts as a draft only the auditee sees; publishing signs
/// it and shows it to the auditor.
#[derive(Serialize, Deserialize)]
struct DisclosureState {
    /// The auditee's handle for it. `body.number` is assigned only when it
    /// is published, so the auditor's numbering says nothing about drafts.
    draft: u32,
    body: DisclosureBody,
    /// draft | published | discarded
    #[serde(with = "status")]
    status: Status,
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

#[derive(Clone, Serialize, Deserialize)]
struct Question {
    version: u32,
    text: String,
    max_steps: u32,
    allow_fine_tuned: bool,
    answer_format: AnswerFormat,
    asked_at_ms: u64,
    /// proposed | accepted | rejected | superseded
    #[serde(with = "status")]
    status: Status,
    note: Option<String>,
    decided_at_ms: Option<u64>,
}

#[derive(Serialize, Deserialize)]
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
    #[serde(with = "status")]
    status: Status,
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

#[derive(Serialize, Deserialize)]
struct RunState {
    /// Restored from a predecessor enclave (see follow-ups).
    #[serde(default)]
    before_move: bool,
    id: String,
    number: u32,
    parent: Option<String>,
    question_version: u32,
    model_id: u32,
    tree: String,
    commitment: String,
    /// The connections the run had (their ids).
    #[serde(default)]
    connections: Vec<u32>,
    /// Every auditor message in this conversation, including inherited ones.
    messages: Vec<(MessageRecord, String)>,
    /// running | awaiting_release | released | declined
    #[serde(with = "status")]
    status: Status,
    steps: u32,
    /// Stored separately, in append-only chunks (`trace_chunks`).
    #[serde(skip)]
    trace: Trace,
    /// The stored chunks of `trace`, in order.
    #[serde(default)]
    trace_chunks: Vec<TraceChunk>,
    /// The manifest as the run started, so a run cut short by an enclave
    /// restart can still be recorded (and released) as failed.
    #[serde(default)]
    template: Option<Manifest>,
    /// Raw bytes recorded in `trace` (capped per run), and whether it hit
    /// its cap. The compressed size is what counts toward TRACE_BYTES.
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

#[derive(Serialize, Deserialize, Clone)]
struct TraceChunk {
    /// sha256 of the stored record, so a successor gets exactly this chunk.
    hash: String,
    entries: usize,
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

/// The other party's invite, derived from the creator's token: the
/// creator's page can always show the link to send, and no plaintext token
/// is stored. It works once (`Store::join`), for a token of the invitee's
/// own that the creator never sees.
pub fn invite_token(creator_token: &str) -> String {
    let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, creator_token.as_bytes());
    hex::encode(ring::hmac::sign(&k, b"attest-invite/1").as_ref())
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Joined {
    pub token_hash: String,
    pub at_ms: u64,
}

fn same_hash(a: &str, b: &str) -> bool {
    a.len() == b.len() && ring::constant_time::verify_slices_are_equal(a.as_bytes(), b.as_bytes()).is_ok()
}

/// "2026-10-31 06:31" for a time in ms since the epoch.
fn fmt_utc(ms: u64) -> String {
    let secs = ms / 1000;
    let (days, rem) = ((secs / 86400) as i64, secs % 86400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}", rem / 3600, rem % 3600 / 60)
}

fn other(r: Role) -> Role {
    match r {
        Role::Auditee => Role::Auditor,
        Role::Auditor => Role::Auditee,
    }
}

const MAX_CONNECTIONS: usize = 12;

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
/// Session memory free before a new session, question, model proposal or
/// message is taken, so a full server refuses work instead of growing.
const SESSION_ALLOWANCE: usize = 1 << 20;
/// Free before a run starts: room for a good part of its trace.
const RUN_ALLOWANCE: usize = 8 << 20;
/// Raw trace content per run: model exchanges in full, tool calls and the
/// agent's own log. Stored compressed.
const MAX_TRACE_BYTES_PER_RUN: usize = 40 << 20;

/// A run's trace entries, each kept LZ4-compressed: tool output and model
/// exchanges are mostly text and JSON, which compress several times over.
#[derive(Default)]
struct Trace {
    entries: Vec<Vec<u8>>,
    /// Compressed bytes held.
    stored: usize,
}

impl Trace {
    fn from_entries(v: &[Value]) -> Self {
        let mut t = Trace::default();
        for e in v {
            t.push(e);
        }
        crate::budget::add(&crate::budget::TRACES, t.stored);
        t
    }

    fn push(&mut self, e: &Value) {
        self.push_compressed(lz4_flex::compress_prepend_size(e.to_string().as_bytes()));
    }

    fn push_compressed(&mut self, c: Vec<u8>) {
        self.stored += c.len();
        self.entries.push(c);
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    /// Entries from `after` on, up to about `max` raw bytes (at least one),
    /// and the index to continue from.
    fn page(&self, after: usize, max: usize) -> (Vec<Value>, usize) {
        let mut out = Vec::new();
        let mut size = 0;
        let mut i = after.min(self.entries.len());
        while i < self.entries.len() {
            let raw = lz4_flex::decompress_size_prepended(&self.entries[i]).unwrap_or_default();
            if !out.is_empty() && size + raw.len() > max {
                break;
            }
            size += raw.len();
            out.push(serde_json::from_slice(&raw).unwrap_or(Value::Null));
            i += 1;
        }
        (out, i)
    }
}

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

    /// Nothing anyone would miss: no question, code, connection, model,
    /// notification setting or run, and the invited party never came. Only
    /// such sessions are evicted early; a full server refuses new ones.
    fn idle(&self) -> bool {
        let st = lock(&self.st);
        // The auditor opening a session they started themselves isn't the
        // invited party joining.
        let invited_joined = st.joined.is_some() || (st.auditor_joined && self.creator != Some(Role::Auditor));
        st.questions.is_empty()
            && st.code.is_none()
            && st.connections.is_empty()
            && st.models.is_empty()
            && st.notify.is_empty()
            && st.runs.is_empty()
            && st.disclosures.is_empty()
            && st.affidavit.is_none()
            && !invited_joined
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
            if let Some(p) = self.persist.get() {
                p.delete_session(&s.id);
            }
            let mut st = lock(&s.st);
            // Runs still going hold their own reference to the code; its
            // stored files go once they end (Bundle's Drop).
            drop(st.code.take());
            st.expired = true;
            let freed: usize = st.runs.iter().map(|r| r.trace.stored).sum();
            crate::budget::sub(&crate::budget::TRACES, freed);
            crate::budget::sub(&crate::budget::STATES, s.measured.swap(0, Ordering::Relaxed));
            // The session is gone from the map; drop what it held.
            st.runs.clear();
            st.disclosures.clear();
        }
    }

    /// A new session started by `creator`; returns the auditee's and the
    /// auditor's tokens.
    pub fn create(&self, creator: Role) -> Result<(Arc<Session>, String, String)> {
        self.sweep();
        let now = now_ms();
        let max = crate::budget::max_sessions();
        let full = lock(&self.sessions).len() >= max;
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
            map.len() < max,
            "this server is at its session limit; try again later"
        );
        crate::budget::ensure_room(SESSION_ALLOWANCE)?;
        let mine = random_hex(32);
        let theirs = invite_token(&mine);
        let (auditee, auditor) = match creator {
            Role::Auditee => (mine, theirs),
            Role::Auditor => (theirs, mine),
        };
        let tx = [watch::channel(0).0, watch::channel(0).0];
        let s = Arc::new(Session {
            id: random_hex(16),
            created_at_ms: now,
            token_hashes: [
                sha256_hex(auditee.as_bytes()),
                sha256_hex(auditor.as_bytes()),
            ],
            creator: Some(creator),
            st: Mutex::new(State { invites: true, ..State::default() }),
            tx,
            dirty: AtomicBool::new(true),
            written: Mutex::new((0, None)),
            measured: Default::default(),
            approvals: Default::default(),
        });
        map.insert(s.id.clone(), s.clone());
        Ok((s, auditee, auditor))
    }

    /// Find the session and the role a token grants. Unknown session and bad
    /// token are indistinguishable.
    pub fn auth(&self, id: &str, token: &str) -> Result<(Arc<Session>, Role)> {
        self.sweep();
        if lock(&self.pending).iter().any(|(sid, _)| sid == id) {
            bail!("this session is temporarily unavailable (its stored state couldn't be read back yet); try again later");
        }
        let s = lock(&self.sessions)
            .get(id)
            .cloned()
            .filter(|s| !s.expired(now_ms()));
        let h = sha256_hex(token.as_bytes());
        if let Some(s) = s {
            let (invites, joined) = {
                let st = lock(&s.st);
                (st.invites, st.joined.clone())
            };
            let invitee = s.creator.map(other);
            for role in [Role::Auditee, Role::Auditor] {
                let hit = same_hash(&h, &s.token_hashes[ri(role)]);
                if !invites || Some(role) != invitee {
                    if hit {
                        return Ok((s, role));
                    }
                    continue;
                }
                // The invitee's slot holds the invite; their token is the joined one.
                if joined.as_ref().is_some_and(|j| same_hash(&h, &j.token_hash)) {
                    return Ok((s, role));
                }
                if hit {
                    match &joined {
                        Some(j) => bail!(
                            "this invite link was already used (at {} UTC); it works only once. If you didn't use it, someone else has this party's access: ask for a new session",
                            fmt_utc(j.at_ms)
                        ),
                        None => bail!("this is an invite link: open it in a browser to join (it gives you a link of your own)"),
                    }
                }
            }
        }
        bail!("unknown session or wrong link")
    }

    /// Use the invite: the invitee gets a token of their own, made here, that
    /// whoever created the session never sees. The invite then stops working.
    pub fn join(&self, ctx: &Arc<Ctx>, id: &str, invite: &str) -> Result<(Arc<Session>, Role, String)> {
        let s = lock(&self.sessions)
            .get(id)
            .cloned()
            .filter(|s| !s.expired(now_ms()))
            .ok_or_else(|| anyhow!("unknown session or wrong link"))?;
        let role = s.creator.map(other).ok_or_else(|| anyhow!("this session has no invite"))?;
        if !same_hash(&sha256_hex(invite.as_bytes()), &s.token_hashes[ri(role)]) {
            bail!("unknown session or wrong link");
        }
        let token = random_hex(32);
        {
            let mut st = lock(&s.st);
            ensure!(st.invites, "this session's links work directly; open it with your link");
            if let Some(j) = &st.joined {
                bail!(
                    "this invite link was already used (at {} UTC); it works only once. If you didn't use it, someone else has this party's access: ask for a new session",
                    fmt_utc(j.at_ms)
                );
            }
            st.joined = Some(Joined { token_hash: sha256_hex(token.as_bytes()), at_ms: now_ms() });
            let text = match role {
                Role::Auditee => "The auditee joined with the invite link.",
                Role::Auditor => "The auditor joined with the invite link.",
            };
            s.event(ctx, &mut st, "joined", text.into(), None, Some(role), false);
        }
        s.dirty.store(true, Ordering::SeqCst);
        Ok((s, role, token))
    }

    pub fn get(&self, id: &str) -> Option<Arc<Session>> {
        lock(&self.sessions).get(id).cloned()
    }

    pub fn len(&self) -> usize {
        lock(&self.sessions).len()
    }

    /// Always 0 now: counting runs of the same question text across the
    /// whole server told any session's auditee whether other customers had
    /// asked it (a membership oracle on unrelated engagements).
    fn note_text_run(&self, _text_sha: &str, _session: &str) -> u32 {
        0
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
        self.dirty.store(true, Ordering::Relaxed);
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
        // The activity feed keeps the latest events only: a party repeating
        // an action can't grow a session without bound.
        if st.events.len() > MAX_EVENTS {
            let extra = st.events.len() - MAX_EVENTS;
            st.events.drain(..extra);
        }
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
        crate::budget::ensure_room(SESSION_ALLOWANCE)?;
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
            "this session has {MAX_QUESTION_VERSIONS} questions already; start a new session"
        );
        // Each question is independent: asking one doesn't replace another.
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
        let msg = format!("The auditor asked question {version}.");
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
            .iter_mut()
            .find(|q| q.version == version)
            .ok_or_else(|| anyhow!("no question {version}"))?;
        ensure!(
            q.status == "proposed",
            "question {version} was already {}",
            q.status
        );
        q.status = if accept { "accepted" } else { "rejected" };
        q.note = note.clone();
        q.decided_at_ms = Some(now_ms());
        let msg = match (accept, &note) {
            (true, _) => format!("The auditee accepted question {version}."),
            (false, Some(n)) => format!("The auditee rejected question {version}: {n}"),
            (false, None) => format!("The auditee rejected question {version}."),
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

    /// Tell the auditee where the code came from (only them: the auditor
    /// sees the commitment).
    /// Install a freshly ingested bundle, replacing (and discarding) any earlier one.
    pub fn set_code(self: &Arc<Self>, ctx: &Arc<Ctx>, role: Role, bundle: Bundle, source: CodeSource) -> Result<Value> {
        ensure!(role == Role::Auditee, "only the auditee provides code");
        // The new index is already counted; the one it replaces isn't freed
        // yet if runs still hold it.
        crate::budget::ensure_room(0)?;
        let bundle = Arc::new(bundle);
        let info = bundle.info.clone();
        let rec = source.record();
        let mut st = lock(&self.st);
        // Runs still holding the old code keep working; its stored files go
        // once nothing does (Bundle's Drop).
        let replaced = st.code.replace(bundle).is_some();
        // Shown to both sides, so only the commitment and where it came
        // from: size and tree hash stay with the auditee until a release.
        let msg = format!(
            "{} (commitment {}){}.",
            rec.statement.trim_end_matches('.'),
            &info.commitment_sha256[..12],
            if replaced { ", replacing the earlier code" } else { "" }
        );
        st.affidavit = Some((info.tree_sha256.clone(), rec));
        self.event(ctx, &mut st, "code_uploaded", msg, None, Some(role), false);
        self.maybe_start(ctx, &mut st);
        Ok(serde_json::to_value(&info)?)
    }

    /// Add a service the agent may use (already checked by connections::connect).
    /// Whether a connection could be added now: checked before the
    /// (network, memory-hungry) discovery, and again when adding.
    pub fn connection_room(&self) -> Result<()> {
        ensure!(lock(&self.st).connections.len() < MAX_CONNECTIONS, "a session has at most {MAX_CONNECTIONS} connections");
        crate::budget::ensure_room(SESSION_ALLOWANCE)
    }

    pub fn add_connection(self: &Arc<Self>, ctx: &Arc<Ctx>, role: Role, mut c: crate::connections::Connection) -> Result<Value> {
        ensure!(role == Role::Auditee, "only the auditee connects services");
        let mut st = lock(&self.st);
        ensure!(st.connections.len() < MAX_CONNECTIONS, "a session has at most {MAX_CONNECTIONS} connections");
        ensure!(!st.connections.iter().any(|x| x.rec.name == c.rec.name), "a connection named {} already exists; give this one another name", c.rec.name);
        c.rec.id = st.connections.iter().map(|x| x.rec.id).max().unwrap_or(0) + 1;
        let rec = c.rec.clone();
        st.connections.push(c);
        let msg = format!(
            "The auditee connected {} ({}){}.",
            rec.name,
            rec.hosts.join(", "),
            rec.identity.as_ref().map(|i| format!(": {i}")).unwrap_or_default()
        );
        self.event(ctx, &mut st, "connection_added", msg, None, Some(role), false);
        self.maybe_start(ctx, &mut st);
        Ok(serde_json::to_value(&rec)?)
    }

    /// Turn tool-call approval on or off for runs started from now on.
    pub fn set_tool_approval(self: &Arc<Self>, ctx: &Arc<Ctx>, role: Role, v: &Value) -> Result<Value> {
        ensure!(role == Role::Auditee, "only the auditee approves tool calls");
        let on = v["enabled"].as_bool().ok_or_else(|| anyhow!("enabled must be true or false"))?;
        let mut st = lock(&self.st);
        if st.tool_approval != on {
            st.tool_approval = on;
            let msg = if on {
                "The auditee will approve or deny each of the agent's tool calls before it runs (from the next run). Certificates say so, with how many were denied."
            } else {
                "The auditee turned off tool-call approval (from the next run)."
            };
            self.event(ctx, &mut st, "tool_approval", msg.into(), None, Some(role), false);
        }
        Ok(json!({"tool_approval": on}))
    }

    /// Let the auditor watch the agent's work: nothing, its steps, or all of it.
    pub fn tool_approval_on(&self) -> bool {
        lock(&self.st).tool_approval
    }

    /// Approve or deny one pending tool call.
    pub fn decide_tool_call(&self, role: Role, id: u64, v: &Value) -> Result<Value> {
        ensure!(role == Role::Auditee, "only the auditee approves tool calls");
        let approve = v["approve"].as_bool().ok_or_else(|| anyhow!("approve must be true or false"))?;
        let reason: String = v["reason"].as_str().unwrap_or("").chars().take(1000).collect();
        self.approvals.decide(id, crate::approvals::Decision { approve, reason })?;
        Ok(json!({"id": id, "approve": approve}))
    }

    pub fn remove_connection(self: &Arc<Self>, ctx: &Arc<Ctx>, role: Role, id: u32) -> Result<Value> {
        ensure!(role == Role::Auditee, "only the auditee removes connections");
        let mut st = lock(&self.st);
        let i = st.connections.iter().position(|c| c.rec.id == id).ok_or_else(|| anyhow!("no connection {id}"))?;
        let c = st.connections.remove(i);
        self.event(ctx, &mut st, "connection_removed", format!("The auditee removed the connection {}.", c.rec.name), None, Some(role), false);
        Ok(json!({"removed": id}))
    }

    pub fn propose_model(self: &Arc<Self>, ctx: &Arc<Ctx>, role: Role, v: &Value) -> Result<Value> {
        crate::budget::ensure_room(SESSION_ALLOWANCE)?;
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
        let qv = st.runs.iter().find(|r| r.id == run_id).map(|r| r.question_version);
        let strict = st.questions.iter().find(|q| Some(q.version) == qv).map(|q| q.answer_format.is_strict());
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
        // The next accepted question can run now.
        self.maybe_start(ctx, &mut st);
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
        crate::budget::ensure_room(SESSION_ALLOWANCE)?;
        let text = clean(v["text"].as_str()).ok_or_else(|| anyhow!("text is required"))?;
        ensure!(
            text.chars().count() <= MAX_MESSAGE_CHARS,
            "message is too long"
        );
        // Every message the auditor sends is visible to the auditee.
        ensure!(!v["blinded"].as_bool().unwrap_or(false), "messages to the agent can't be hidden from the auditee");
        let blinded = false;
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
        // The same answer for every run from before a move, whether or not
        // it had finished: which ones had says when they ended.
        ensure!(
            !parent.before_move,
            "run {} ran before this service moved to a new enclave and can't be continued; revise the question to run it again",
            parent.number
        );
        // A follow-up continues that run as agreed: same code, same model and
        // account. If either changed since, the old conversation (and its
        // excerpts of the old code) mustn't mix with the new, nor new code go
        // to a model or account that was replaced.
        let model = st.models.iter().find(|m| m.id == parent.model_id).unwrap();
        let tree = st.code.as_ref().map(|c| c.info.tree_sha256.clone()).unwrap_or_default();
        let conns: Vec<u32> = st.connections.iter().map(|c| c.rec.id).collect();
        ensure!(
            model.status == "approved" && tree == parent.tree && conns == parent.connections,
            "the code, the connected services or the model changed since run {}; revise the question to run it again",
            parent.number
        );
        // The agent can send requests to services the auditee runs, so a
        // message hidden from the auditee could reach them that way.
        ensure!(
            !blinded || conns.is_empty(),
            "blinded messages aren't possible with connected services: the agent's requests to them could carry the message to the auditee"
        );
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
        // One run at a time, and not while a run awaits the auditee's
        // decision either: a new run starting would tell the auditor when
        // the earlier one finished.
        if st.runs.iter().any(|r| r.status == "running" || r.status == "awaiting_release") {
            return;
        }
        // The earliest accepted question that hasn't run yet; otherwise the
        // latest accepted one (it reruns when the model or what's connected
        // changes).
        let accepted = || st.questions.iter().filter(|q| q.status == "accepted");
        let Some(q) = accepted()
            .find(|q| !st.runs.iter().any(|r| r.parent.is_none() && r.question_version == q.version))
            .or_else(|| accepted().last())
        else {
            return;
        };
        // Something to investigate: code, connected services, or both.
        let tree = match &st.code {
            Some(code) => {
                if !st.affidavit.as_ref().is_some_and(|(t, _)| t == &code.info.tree_sha256) {
                    return;
                }
                code.info.tree_sha256.clone()
            }
            None if !st.connections.is_empty() => String::new(),
            None => return,
        };
        let conns: Vec<u32> = st.connections.iter().map(|c| c.rec.id).collect();
        let Some(m) = st.models.iter().rev().find(|m| m.status == "approved") else {
            return;
        };
        if llm::is_fine_tuned(m.provider, &m.model) && !q.allow_fine_tuned {
            return;
        }
        if jailed_conflict(st, m).is_some() {
            return;
        }
        let (qv, mid) = (q.version, m.id);
        if st.runs.iter().any(|r| {
            r.parent.is_none() && r.question_version == qv && r.model_id == mid && r.tree == tree && r.connections == conns
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
        crate::budget::ensure_room(RUN_ALLOWANCE)?;
        let q = st
            .questions
            .iter()
            .find(|q| q.version == spec.question_version)
            .cloned()
            .ok_or_else(|| anyhow!("no question"))?;
        let has_code = st.code.is_some();
        ensure!(has_code || !st.connections.is_empty(), "nothing is connected");
        let bundle = match &st.code {
            Some(b) => b.clone(),
            None => Arc::new(Bundle::empty(&self.id, ctx.blobs.clone(), ctx.cache.clone())),
        };
        let affidavit = match &st.affidavit {
            Some((_, a)) if has_code => a.clone(),
            _ => AffidavitRecord {
                organization: String::new(),
                repo_url: None,
                git_commit: None,
                statement: "No code was connected.".into(),
                confirmed_at_ms: now_ms(),
                fetched_by_enclave: false,
            },
        };
        let connections = st.connections.clone();
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
                    has_code.then_some((bundle.info.file_count, bundle.info.total_bytes)),
                    &connections.iter().map(|c| c.describe()).collect::<Vec<_>>(),
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
        let mut prior_trees: Vec<String> = st.runs.iter().map(|r| r.tree.clone()).filter(|t| !t.is_empty()).collect();
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
        let started_at_ms = now_ms();
        let template = Manifest {
            schema: "attest/manifest/v2".into(),
            session_id: self.id.clone(),
            run_id: id.clone(),
            run_number: number,
            parent_run_id: spec.parent.clone(),
            boot_id: ctx.info.boot_id.clone(),
            started_at_ms,
            finished_at_ms: 0,
            question: question.clone(),
            auditor_messages: messages.iter().map(|(r, _)| r.clone()).collect(),
            affidavit: affidavit.clone(),
            code: bundle.info.clone(),
            has_code,
            connections: connections.iter().map(|c| c.rec.clone()).collect(),
            tool_approval: st.tool_approval.then(ToolApproval::default),
            model: model_info.clone(),
            harness: ctx.info.harness.clone(),
            activity: Activity::default(),
            instruction_scan: InstructionScan {
                patterns_version: scan::PATTERNS_VERSION.into(),
                whole_bundle: bundle.scan_all(),
                files_read: ScanCounts::default(),
            },
            history: history.clone(),
            outcome: Outcome::Completed,
            detail: "full".into(),
            ran_on_boot_id: None,
        };
        st.runs.push(RunState {
            before_move: false,
            id: id.clone(),
            number,
            parent: spec.parent.clone(),
            question_version: q.version,
            model_id: m.id,
            tree: if has_code { bundle.info.tree_sha256.clone() } else { String::new() },
            commitment: bundle.info.commitment_sha256.clone(),
            connections: connections.iter().map(|c| c.rec.id).collect(),
            messages: messages.clone(),
            status: "running",
            steps: 0,
            trace_bytes: trace.iter().map(|e| e.to_string().len()).sum(),
            trace: Trace::from_entries(&trace),
            trace_chunks: Vec::new(),
            template: Some(template),
            trace_full: false,
            turns: None,
            full: None,
            certificate: None,
            verdict: None,
            outcome: None,
            decision_note: None,
            started_at_ms,
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

        let job = RunJob {
            approval: st.tool_approval,
            session: self.clone(),
            ctx: ctx.clone(),
            run_id: id.clone(),
            number,
            parent: spec.parent,
            client,
            bundle,
            has_code,
            connections,
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
        let mut actions = next_actions(&st, role, &self.id);
        if role == Role::Auditee && !self.approvals.list().is_empty() {
            actions.insert(0, json!({"action": "decide_tool_calls", "method": "GET", "path": format!("/api/sessions/{}/tool-calls", self.id),
                "description": "The agent is waiting: approve or deny each pending tool call (POST /api/sessions/ID/tool-calls/CALL_ID with {\"approve\": true|false, \"reason\": \"...\"})."}));
        }
        json!({
            "session_id": self.id,
            "role": role,
            "creator": self.creator,
            "created_at_ms": self.created_at_ms,
            "version": st.versions[ri(role)],
            "boot_id": ctx.info.boot_id,
            "auditor_joined": st.auditor_joined,
            // When the other party's one-time invite was used (null: not
            // yet, or a session from before invites).
            "invite": if st.invites { json!({"used_at_ms": st.joined.as_ref().map(|j| j.at_ms)}) } else { Value::Null },
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
            "connections": st.connections.iter().map(|c| &c.rec).collect::<Vec<_>>(),
            "tool_approval": st.tool_approval,
            "pending_tool_calls": if role == Role::Auditee { json!(self.approvals.list()) } else { Value::Null },
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
            "next_actions": actions,
        })
    }

    pub fn trace(&self, role: Role, run_id: &str, after: usize) -> Result<Value> {
        let st = lock(&self.st);
        // Only the auditee sees what the agent did: an auditor who could
        // read the transcript could steer the agent into quoting anything.
        ensure!(role == Role::Auditee, "only the auditee can see the agent's trace");
        let r = st
            .runs
            .iter()
            .find(|r| r.id == run_id)
            .ok_or_else(|| anyhow!("no such run"))?;
        Ok(
            {
                // Pages of up to 4 MiB: a run's trace can be 40 MiB.
                let (mut entries, next) = r.trace.page(after, 4 << 20);
                // A jailed agent's model calls, made readable.
                for e in entries.iter_mut() {
                    if e["type"] == "model_exchange" {
                        e["turn"] = exchange_turn(e);
                    }
                }
                json!({"run_id": r.id, "status": r.status, "next": next, "more": next < r.trace.len(), "entries": entries})
            },
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
        crate::budget::ensure_room(SESSION_ALLOWANCE + 2 * MAX_DISCLOSED_FILE as usize)?;
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
                let _code_memory = reserve_code_memory(&bundle, 1).await?;
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
        // Signed by this boot, which verifiers check against the body.
        d.body.boot_id = ctx.info.boot_id.clone();
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
    has_code: bool,
    connections: Vec<crate::connections::Connection>,
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
    /// The auditee approves each tool call.
    approval: bool,
}

impl RunJob {
    async fn execute(self) {
        let ctx = self.ctx.clone();
        let _permit = ctx.slots.acquire().await;
        let copies = if self.harness_job.is_some() { 2 } else { 1 };
        // Held until the run ends; a refusal ends the run as failed below.
        let code_memory = reserve_code_memory(&self.bundle, copies).await;
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
                    // The stored size is unknown until compressed; the raw
                    // size bounds it, so check the global budget with that.
                    if r.trace_bytes + size > MAX_TRACE_BYTES_PER_RUN || crate::budget::ensure_room(size).is_err() {
                        r.trace_full = true;
                        r.trace.push(&json!({"type": "error", "content": "the trace reached its size limit; later steps aren't recorded (the run continues)"}));
                        return;
                    }
                    r.trace_bytes += size;
                    let before = r.trace.stored;
                    for e in &entries {
                        r.trace.push(e);
                    }
                    crate::budget::add(&crate::budget::TRACES, r.trace.stored - before);
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
        let gate = self.approval.then(|| {
            let s = self.session.clone();
            let agent = self.harness_job.as_ref().map(|h| h.0.id()).unwrap_or("builtin");
            crate::approvals::Gate::new(
                self.session.approvals.clone(),
                &self.run_id,
                self.number,
                agent,
                Arc::new(move || {
                    let mut st = lock(&s.st);
                    s.changed_for(&mut st, Role::Auditee);
                }),
                progress.clone(),
            )
        });
        let out = match &code_memory {
            Err(e) => failed_output(&format!("{e:#}")),
            Ok(_) => {
                let work = std::panic::AssertUnwindSafe(self.agent(progress.clone(), gate.clone()));
                match tokio::time::timeout(deadline, futures_util::FutureExt::catch_unwind(work)).await {
                    Ok(Ok(out)) => out,
                    Ok(Err(_)) => failed_output("the run failed inside the enclave (an internal error)"),
                    Err(_) => failed_output(&format!(
                        "the run did not finish within its {} minutes",
                        deadline.as_secs() / 60
                    )),
                }
            }
        };
        self.session.approvals.cancel_run(&self.run_id);
        let counts = gate.map(|g| *g.counts.lock().unwrap());
        self.finish(out, started_at_ms, ticker, counts);
    }

    /// Load the code and run the agent.
    async fn agent(&self, progress: Arc<dyn Fn(Vec<Value>) + Send + Sync>, gate: Option<crate::approvals::Gate>) -> run::AgentOutput {
        // Load all the code into enclave memory first; from here on the
        // host sees no reads that depend on what the agent does.
        let pin = self.bundle.pin().await;
        match (&pin, &self.harness_job) {
            (Err(e), _) => run::AgentOutput {
                connections: vec![],
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
                    gate,
                )
                .await
            }
            (Ok(_), None) => {
                let sandbox = self.ctx.sandbox.get().cloned();
                run::agent_loop(
                    &self.client,
                    &self.bundle,
                    self.has_code,
                    self.connections.clone(),
                    &self.ctx.net,
                    sandbox,
                    self.turns.clone(),
                    self.question.max_steps,
                    &self.question.answer_format,
                    &*progress,
                    gate.as_ref(),
                )
                .await
            }
        }
    }

    /// Record the run's result and start whatever is queued next.
    fn finish(self, out: run::AgentOutput, started_at_ms: u64, ticker: AbortOnDrop, approvals: Option<crate::approvals::Counts>) {
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
            has_code: self.has_code,
            connections: if out.connections.is_empty() {
                self.connections.iter().map(|c| c.rec.clone()).collect()
            } else {
                out.connections.clone()
            },
            tool_approval: approvals.map(|c| ToolApproval { approved: c.approved, denied: c.denied, timed_out: c.timed_out, withheld: c.withheld }),
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
            ran_on_boot_id: None,
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
/// Memory for copies of the code held for runs and disclosures: the copy
/// loaded into enclave memory, and for jailed agents the jail's own copy.
/// 30% of the enclave's memory, in MiB; work waits for room. (Jailed
/// agents' own memory has a separate cap; see cgroups::jails_memory.)
fn code_memory() -> &'static tokio::sync::Semaphore {
    static S: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    S.get_or_init(|| {
        tokio::sync::Semaphore::new((crate::cgroups::mem_total() / 10 * 3 >> 20).max(1) as usize)
    })
}

/// Reserve room for `copies` copies of `bundle` (a repository bigger than
/// the whole budget gets the whole budget).
/// Code needing more than the whole pool is refused, not squeezed in.
async fn reserve_code_memory(bundle: &Bundle, copies: u64) -> Result<tokio::sync::SemaphorePermit<'static>> {
    let budget = (crate::cgroups::mem_total() / 10 * 3 >> 20).max(1);
    // Files take whole pages in memory, plus inode and directory entries:
    // a repository of tiny files costs far more than its byte count.
    let per_copy = (bundle.info.total_bytes as u64).saturating_add((bundle.info.file_count as u64).saturating_mul(4096 + 512));
    let mib = (per_copy.saturating_mul(copies) >> 20) + 1;
    ensure!(
        mib <= budget,
        "this code needs about {mib} MiB of enclave memory to load ({} files), more than the {budget} MiB this server has for code; share a smaller repository",
        bundle.info.file_count
    );
    Ok(code_memory()
        .acquire_many(mib as u32)
        .await
        .expect("the code memory semaphore is never closed"))
}

/// Aborts a background task when dropped.
pub struct AbortOnDrop(pub tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn failed_output(message: &str) -> run::AgentOutput {
    run::AgentOutput {
        connections: vec![],
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
    for c in &mut m.connections {
        c.calls = 0;
    }
    m.instruction_scan = InstructionScan::default();
    m.history.prior_code_trees_in_session.clear();
    m.history.same_question_text_other_sessions = 0;
    if let Outcome::Error { message } = &mut m.outcome {
        *message = "details withheld".into();
    }
    b
}

fn sign_certificate(ctx: &Ctx, body: &CertificateBody) -> Result<Certificate> {
    // A certificate names the boot that signs it (verifiers check its
    // attestation). A run from an earlier boot of this lineage says so.
    let mut body = body.clone();
    let m = &mut body.manifest;
    if m.boot_id != ctx.info.boot_id {
        m.ran_on_boot_id.get_or_insert(m.boot_id.clone());
        m.boot_id = ctx.info.boot_id.clone();
    }
    Ok(Certificate {
        enclave_info_json: ctx.info_json.clone(),
        boot_document_b64: ctx.boot_doc_b64.clone(),
        signed: sign::sign(&ctx.signing, DOMAIN_CERTIFICATE, &body)?,
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

/// Where the session's code came from. Who the auditee is, and what they
/// vouch for, is settled between the parties outside the session; the
/// record states only what this enclave knows.
pub enum CodeSource {
    /// Fetched by the enclave itself, so the repository and commit are facts.
    Github { repo: String, commit: String },
    /// Uploaded by the auditee, with the origin they say it has (unchecked).
    Upload { repo_url: Option<String>, git_commit: Option<String> },
}

impl CodeSource {
    pub fn record(&self) -> AffidavitRecord {
        let fetched_by_enclave = matches!(self, CodeSource::Github { .. });
        let (repo_url, git_commit, statement) = match self {
            CodeSource::Github { repo, commit } => {
                let url = format!("https://github.com/{repo}");
                let st = format!("The enclave fetched this code from {url} at commit {commit}.");
                (Some(url), Some(commit.clone()), st)
            }
            CodeSource::Upload { repo_url, git_commit } => {
                let st = match (repo_url, git_commit) {
                    (None, None) => "The auditee uploaded this code; its origin is not recorded.".to_string(),
                    _ => format!(
                        "The auditee uploaded this code and says it is {} at commit {} (not checked by the enclave).",
                        repo_url.as_deref().unwrap_or("(repository not named)"),
                        git_commit.as_deref().unwrap_or("(commit not named)"),
                    ),
                };
                (repo_url.clone(), git_commit.clone(), st)
            }
        };
        AffidavitRecord { organization: String::new(), repo_url, git_commit, statement, confirmed_at_ms: now_ms(), fetched_by_enclave }
    }
}

/// Why the approved model's agent can't run here, if it can't: the jailed
/// agents (harnesses.rs) read code only and don't get connected services.
fn jailed_conflict(st: &State, m: &ModelProposal) -> Option<&'static str> {
    crate::harnesses::Agent::parse(&m.agent)?;
    if !st.connections.is_empty() {
        Some("Connected services work only with the built-in agent for now. Choose it in the model step, or remove the connections.")
    } else if st.code.is_none() {
        Some("This agent needs code. Connect a repository, or choose the built-in agent.")
    } else {
        None
    }
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
        None if role == Role::Auditor => return "Ask your question below.".into(),
        None => return "Waiting for the auditor to ask a question.".into(),
        Some("proposed") if role == Role::Auditee => return "The auditor asked a question. Accept or reject it below.".into(),
        Some("proposed") => return "Waiting for the auditee to accept your question.".into(),
        Some("rejected") => {
            return "The auditee rejected the question. Waiting for the auditor to revise it."
                .into()
        }
        _ => {}
    }
    let mut missing = Vec::new();
    match (&st.code, &st.affidavit) {
        (None, _) if st.connections.is_empty() => missing.push("the auditee to connect code or services"),
        (None, _) => {}
        (Some(c), Some((t, _))) if t == &c.info.tree_sha256 => {}
        _ => missing.push("the auditee to provide code"),
    }
    if let Some(m) = st.models.iter().rev().find(|m| m.status == "approved") {
        if let Some(why) = jailed_conflict(st, m) {
            return why.into();
        }
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
                return "The approved model is, or may be, a fine-tune (every Azure deployment counts), which the question does not allow. Choose another model or allow fine-tunes.".into();
            }
        }
        if st.runs.is_empty() {
            return "Starting.".into();
        }
        return "Done. The auditor can send a follow-up or revise the question.".into();
    }
    if role == Role::Auditee {
        let todo: Vec<&str> = missing
            .iter()
            .map(|m| match *m {
                "the auditee to connect code or services" => "connect code or services",
                "the auditee to provide code" => "provide code",
                "the auditee to approve a model" => "approve the proposed model",
                _ => "choose a model and API key",
            })
            .collect();
        let mut t = todo.join(" and ");
        if let Some(c) = t.get_mut(0..1) {
            c.make_ascii_uppercase();
        }
        return format!("{t} below.");
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
                        "Ask the agent to revise its answer (the auditee sees your message).",
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
                out.push(a(
                    "import_github",
                    "POST",
                    format!("{base}/code/github"),
                    "Or have the enclave fetch it from GitHub: {repo: \"owner/name\", ref, token (omit for a public repository)}.",
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
