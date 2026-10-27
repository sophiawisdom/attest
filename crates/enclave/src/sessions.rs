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
    openrouter_zdr: bool,
    mock_endpoint: Option<String>,
    /// "builtin" or "codex".
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
            "openrouter_zdr": self.openrouter_zdr, "status": self.status,
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
    turns: Option<Vec<Turn>>,
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

fn clean(s: Option<&str>) -> Option<String> {
    s.map(|x| x.trim().to_string()).filter(|x| !x.is_empty())
}

impl Store {
    pub fn create(&self) -> Result<(Arc<Session>, String, String)> {
        let mut map = self.sessions.lock().unwrap();
        let now = now_ms();
        let expired: Vec<String> = map
            .iter()
            .filter(|(_, s)| now.saturating_sub(s.created_at_ms) >= SESSION_TTL_MS)
            .map(|(k, _)| k.clone())
            .collect();
        for id in expired {
            if let Some(s) = map.remove(&id) {
                if let Some(b) = s.st.lock().unwrap().code.take() {
                    tokio::spawn(async move { b.discard().await });
                }
            }
        }
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
        let s = self.sessions.lock().unwrap().get(id).cloned();
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
        self.sessions.lock().unwrap().get(id).cloned()
    }

    fn note_text_run(&self, text_sha: &str, session: &str) -> u32 {
        let mut idx = self.text_index.lock().unwrap();
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
        let _ = self.tx[i].send(st.versions[i]);
    }

    /// Email `role` now, if they asked for email.
    fn email(&self, ctx: &Arc<Ctx>, role: Role, text: String) {
        let prefs = self.st.lock().unwrap().notify.get(&role).cloned();
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
        let mut st = self.st.lock().unwrap();
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
        let mut st = self.st.lock().unwrap();
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
        let note = clean(v["note"].as_str());
        let mut st = self.st.lock().unwrap();
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
        let mut st = self.st.lock().unwrap();
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
            clean(v["organization"].as_str()).ok_or_else(|| anyhow!("organization is required"))?;
        let repo_url = clean(v["repo_url"].as_str());
        let git_commit = clean(v["git_commit"].as_str());
        let tree = clean(v["tree_sha256"].as_str())
            .ok_or_else(|| anyhow!("tree_sha256 of the uploaded code is required"))?;
        let mut st = self.st.lock().unwrap();
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
        ensure!(api_key.len() < 1000, "key too long");
        let mock_endpoint = clean(v["mock_endpoint"].as_str());
        let agent = clean(v["agent"].as_str()).unwrap_or_else(|| "builtin".into());
        crate::harnesses::supports(&agent, provider)?;
        ensure!(
            provider != Provider::Mock || mock_endpoint.is_some(),
            "mock_endpoint is required for the mock provider"
        );
        let api_key_given = !api_key.is_empty();
        let mut st = self.st.lock().unwrap();
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
            openrouter_zdr: v["openrouter_zdr"].as_bool().unwrap_or(false),
            mock_endpoint,
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
        let note = clean(v["note"].as_str());
        let own_key = clean(v["api_key"].as_str());
        let mut st = self.st.lock().unwrap();
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
            ensure!(k.len() < 1000, "key too long");
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
        let note = clean(v["note"].as_str());
        let mut st = self.st.lock().unwrap();
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
        let mut st = self.st.lock().unwrap();
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
        let mut st = self.st.lock().unwrap();
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
        let mut st = self.st.lock().unwrap();
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
        let Some(q) = st.questions.last() else { return };
        if q.status != "accepted" || st.runs.iter().any(|r| r.status == "running") {
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
            m.provider,
            m.model.clone(),
            m.api_key.clone(),
            m.openrouter_zdr,
            m.mock_endpoint.clone(),
        )?;
        let model_info = ModelInfo {
            provider: m.provider,
            endpoint: llm::endpoint(m.provider).0.to_string(),
            requested_model: m.model.clone(),
            fine_tuned: llm::is_fine_tuned(m.provider, &m.model),
            proposed_by: m.by,
            approved_at_ms: m.decided_at_ms.unwrap_or(m.proposed_at_ms),
            response_models: vec![],
            key_owner: None,
            upstream_providers: vec![],
            openrouter_zdr: (m.provider == Provider::Openrouter).then_some(m.openrouter_zdr),
            agent: if m.agent == "codex" {
                format!("codex {}", crate::harnesses::CODEX_VERSION)
            } else {
                "builtin".into()
            },
            key_from: Some(m.key_from),
        };
        let harness_job = (m.agent == "codex").then(|| {
            (
                m.provider,
                m.model.clone(),
                m.api_key.clone(),
                m.openrouter_zdr,
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
            turns: None,
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
            harness_prompt: crate::harnesses::codex_prompt(
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
        let st = self.st.lock().unwrap();
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
        let st = self.st.lock().unwrap();
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
        let bundle = {
            let st = self.st.lock().unwrap();
            ensure!(
                st.disclosures.len() < MAX_DISCLOSURES,
                "this session has {MAX_DISCLOSURES} disclosures already"
            );
            st.code
                .clone()
                .ok_or_else(|| anyhow!("upload code first"))?
        };
        let note = clean(v["note"].as_str());
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
        let mut st = self.st.lock().unwrap();
        ensure!(
            st.code.as_ref().is_some_and(|c| Arc::ptr_eq(c, &bundle)),
            "the code was replaced while the disclosure was being prepared; try again"
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
        let mut st = self.st.lock().unwrap();
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
        let st = self.st.lock().unwrap();
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

    pub fn certificate(&self, role: Role, run_id: &str) -> Result<Certificate> {
        let st = self.st.lock().unwrap();
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
        }
        r.certificate
            .clone()
            .ok_or_else(|| anyhow!("run {} has not finished", r.number))
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
    harness_job: Option<(Provider, String, String, bool)>,
    harness_prompt: String,
}

impl RunJob {
    async fn execute(self) {
        let _permit = self.ctx.slots.acquire().await;
        let started_at_ms = now_ms();
        let session = self.session.clone();
        let run_id = self.run_id.clone();
        let progress: Arc<dyn Fn(Vec<Value>) + Send + Sync> =
            Arc::new(move |entries: Vec<Value>| {
                let mut st = session.st.lock().unwrap();
                if let Some(r) = st.runs.iter_mut().find(|r| r.id == run_id) {
                    r.steps += entries
                        .iter()
                        .filter(|e| e["type"] == "assistant" || e["type"] == "model_exchange")
                        .count() as u32;
                    r.trace.extend(entries);
                }
                // No wake-up here: the ticker below wakes the auditee on a
                // fixed schedule, so the timing of their trace fetches (which
                // the parent sees) doesn't follow what the agent does.
            });
        let ticker = {
            let session = self.session.clone();
            tokio::spawn(async move {
                let mut t = tokio::time::interval(Duration::from_secs(5));
                loop {
                    t.tick().await;
                    let mut st = session.st.lock().unwrap();
                    session.changed_for(&mut st, Role::Auditee);
                }
            })
        };
        // Email the auditee at the run's time limit, whether or not it has
        // finished: a completion-triggered email would carry its timing.
        {
            let (session, ctx, n) = (self.session.clone(), self.ctx.clone(), self.number);
            let limit = run_time_limit(self.question.max_steps);
            tokio::spawn(async move {
                tokio::time::sleep(limit).await;
                let decided =
                    session.st.lock().unwrap().runs.iter().any(|r| {
                        r.number == n && (r.status == "released" || r.status == "declined")
                    });
                if decided {
                    return;
                }
                session.email(&ctx, Role::Auditee, format!("Run {n} has had its full time ({} min). Once it has finished, review it and decide whether to release it.", limit.as_secs() / 60));
            });
        }
        // Load all the code into enclave memory first; from here on the
        // host sees no reads that depend on what the agent does.
        let pin = self.bundle.pin().await;
        let out = match (&pin, &self.harness_job) {
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
            (Ok(_), Some((provider, model, key, zdr))) => {
                let timeout = run_time_limit(self.question.max_steps);
                crate::harnesses::run_codex(
                    self.ctx.net.clone(),
                    &self.run_id,
                    &self.bundle,
                    *provider,
                    model,
                    key,
                    *zdr,
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
        };

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
        };
        let mut manifest = manifest;
        if self.question.answer_format.is_strict() {
            minimize_for_strict_format(&mut manifest);
        }
        let body = CertificateBody {
            manifest,
            verdict: out.verdict.clone(),
        };
        let certificate =
            sign::sign(&self.ctx.signing, DOMAIN_CERTIFICATE, &body).map(|signed| Certificate {
                enclave_info_json: self.ctx.info_json.clone(),
                boot_document_b64: self.ctx.boot_doc_b64.clone(),
                signed,
            });

        let mut st = self.session.st.lock().unwrap();
        let Some(r) = st.runs.iter_mut().find(|r| r.id == self.run_id) else {
            return;
        };
        r.status = "awaiting_release";
        r.finished_at_ms = Some(now_ms());
        r.turns = Some(out.turns);
        r.verdict = out.verdict.clone();
        r.outcome = Some(out.outcome.clone());
        match certificate {
            Ok(c) => r.certificate = Some(c),
            Err(e) => crate::log(&format!("run {}: signing failed: {e:#}", self.run_id)),
        }
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
        ticker.abort();

        let s = self.session.clone();
        drop(st);
        let mut st = s.st.lock().unwrap();
        s.maybe_start(&self.ctx, &mut st);
    }
}

/// How long a run may take; also when the auditee is emailed about it.
fn run_time_limit(max_steps: u32) -> Duration {
    Duration::from_secs((max_steps as u64 * 20).clamp(300, 1800))
}

/// With a strict answer format, the result should carry little beyond the
/// answer. Activity numbers are steered by the model, so they are rounded up
/// to powers of two; per-file detail is dropped; times are rounded to the hour.
fn minimize_for_strict_format(m: &mut Manifest) {
    let p2 = |n: u64| if n == 0 { 0 } else { n.next_power_of_two() };
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
    if role == Role::Auditor && r.status == "awaiting_release" && !auditor_sees_finish(st, r) {
        v["status"] = json!("running");
        v["finished_at_ms"] = Value::Null;
    }
    let visible_result = role == Role::Auditee || r.status == "released";
    if visible_result {
        v["code_tree_sha256"] = json!(r.tree);
        v["verdict"] = json!(r.verdict);
        v["outcome"] = json!(r.outcome);
        v["has_certificate"] = json!(r.certificate.is_some());
        if let Some(c) = &r.certificate {
            if let Ok(body) = serde_json::from_str::<CertificateBody>(&c.signed.body) {
                v["flags"] = json!(attest_core::verify::manifest_warnings(&body.manifest));
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
