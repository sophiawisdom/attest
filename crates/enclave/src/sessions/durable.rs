//! Durable session state: written sealed to the parent's store (persist.rs)
//! a couple of seconds after each change, and read back by a successor
//! enclave of the same image after a handoff (handoff.rs).
//!
//! Each session is a set of records:
//!   head/{s}          which snapshot is current: its generation, slot, and
//!                     the hashes of its parts
//!   snap/{s}/{i}      the snapshot
//!   Head and snapshot rotate through SLOTS slots, so the last few versions
//!   stay readable and a write cut short never damages the current one. A
//!   head is referred to as "SLOT:HASH".
//!   code/{id}/{i}     an upload's index and sealing key (written once)
//!   trace/{run}/{k}   a run's trace, in append-only chunks
//! Every record but the head is named by hash from the record before it, and
//! a handoff carries each head's hash, so the successor gets exactly the
//! state the giver last wrote.
//!
//! The lineage also keeps an index of its sessions (INDEX_SID/INDEX), so a
//! promoted standby (replica.rs), which was given no heads, finds every
//! session and reads the newest head of each that opens. Nothing proves
//! those are the latest: the parent could serve older ones and hide recent
//! changes, but not invent any.

use super::*;
use anyhow::Context as _;

/// Head and snapshot slots per session.
const SLOTS: u64 = 4;

/// The lineage's session index: a record outside any session.
const INDEX_SID: &str = "~lineage";
const INDEX: &str = "sessions";

/// How often changed sessions are written.
pub const WRITE_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Serialize, Deserialize)]
struct Head {
    generation: u64,
    slot: u64,
    parts: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct CodeRef {
    name: String,
    parts: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct EventRecord {
    seqs: [u64; 2],
    at_ms: u64,
    kind: String,
    text: String,
    important: bool,
}

#[derive(Serialize, Deserialize)]
struct NotifyRecord {
    email: Option<String>,
    email_status: String,
    changes: u32,
}

/// What a snapshot holds, borrowed from the live state to write it...
#[derive(Serialize)]
struct SnapshotRef<'a> {
    id: &'a str,
    created_at_ms: u64,
    token_hashes: &'a [String; 2],
    creator: Option<Role>,
    versions: [u64; 2],
    auditor_joined: bool,
    questions: &'a Vec<Question>,
    code: Option<CodeRef>,
    affidavit: &'a Option<(String, AffidavitRecord)>,
    models: &'a Vec<ModelProposal>,
    runs: &'a Vec<RunState>,
    events: Vec<EventRecord>,
    notify: Vec<(Role, NotifyRecord)>,
    event_counts: [u64; 2],
    disclosures: &'a Vec<DisclosureState>,
    connections: &'a Vec<crate::connections::Connection>,
    tool_approval: bool,
    auditor_watch: &'a str,
}

/// ...and owned, to read it back.
#[derive(Deserialize)]
struct Snapshot {
    id: String,
    created_at_ms: u64,
    token_hashes: [String; 2],
    #[serde(default)]
    creator: Option<Role>,
    versions: [u64; 2],
    auditor_joined: bool,
    questions: Vec<Question>,
    code: Option<CodeRef>,
    affidavit: Option<(String, AffidavitRecord)>,
    models: Vec<ModelProposal>,
    runs: Vec<RunState>,
    events: Vec<EventRecord>,
    notify: Vec<(Role, NotifyRecord)>,
    event_counts: [u64; 2],
    disclosures: Vec<DisclosureState>,
    #[serde(default)]
    connections: Vec<crate::connections::Connection>,
    #[serde(default)]
    tool_approval: bool,
    #[serde(default)]
    auditor_watch: String,
}

fn code_name(b: &Bundle) -> String {
    // The commitment is salted, so it names this one upload.
    format!("code/{}", &b.info.commitment_sha256[..32])
}

/// Trace entries (each already compressed) as one record: count, then
/// length-prefixed entries.
fn encode_entries(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut out = (entries.len() as u32).to_le_bytes().to_vec();
    for e in entries {
        out.extend_from_slice(&(e.len() as u32).to_le_bytes());
        out.extend_from_slice(e);
    }
    out
}

fn decode_entries(b: &[u8]) -> Result<Vec<Vec<u8>>> {
    fn take<'a>(b: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
        ensure!(b.len() >= n, "trace chunk is truncated");
        let (h, t) = b.split_at(n);
        *b = t;
        Ok(h)
    }
    fn u32_at(b: &mut &[u8]) -> Result<usize> {
        Ok(u32::from_le_bytes(take(b, 4)?.try_into().unwrap()) as usize)
    }
    let mut b = b;
    let count = u32_at(&mut b)?;
    let mut out = Vec::with_capacity(count.min(1 << 16));
    for _ in 0..count {
        let n = u32_at(&mut b)?;
        out.push(take(&mut b, n)?.to_vec());
    }
    ensure!(b.is_empty(), "trace chunk has trailing bytes");
    Ok(out)
}

const INTERRUPTED: &str = "the run was interrupted: the enclave serving this session restarted or moved. Ask again or send a follow-up to run it anew.";

impl Session {
    /// Write this session's state (it changed since the last write).
    async fn write_state(&self, p: &crate::persist::Persist) -> Result<()> {
        self.write_state_with(p, false).await
    }

    /// Also running runs' traces so far: for the write before a handoff.
    async fn write_state_full(&self, p: &crate::persist::Persist) -> Result<()> {
        self.write_state_with(p, true).await
    }

    async fn write_state_with(&self, p: &crate::persist::Persist, include_running: bool) -> Result<()> {
        self.dirty.store(false, Ordering::Relaxed);
        let r = self.write_state_inner(p, include_running).await;
        if r.is_err() {
            self.dirty.store(true, Ordering::Relaxed);
        }
        r
    }

    async fn write_state_inner(&self, p: &crate::persist::Persist, include_running: bool) -> Result<()> {
        // What to write before the snapshot: an upload's index (once) and
        // trace entries added since the last write.
        let (code, traces) = {
            let st = lock(&self.st);
            if st.expired {
                return Ok(());
            }
            let code = st.code.clone().filter(|b| lock(&b.persisted).is_none());
            let traces: Vec<(String, usize, Vec<Vec<u8>>)> = st
                .runs
                .iter()
                // A running run's trace waits until it ends (or a handoff):
                // writing it as it grows would show the parent, through the
                // sizes and timing of the writes, what the agent is doing.
                .filter(|r| include_running || r.status != "running")
                .filter_map(|r| {
                    let done: usize = r.trace_chunks.iter().map(|c| c.entries).sum();
                    (r.trace.len() > done).then(|| {
                        (r.id.clone(), r.trace_chunks.len(), r.trace.entries[done..].to_vec())
                    })
                })
                .collect();
            (code, traces)
        };
        if let Some(b) = code {
            let manifest = serde_json::to_vec(&b.manifest())?;
            let parts = p.put_large(&self.id, &code_name(&b), &manifest).await?;
            *lock(&b.persisted) = Some(parts);
        }
        let mut chunks = Vec::new();
        for (run, k, entries) in traces {
            let hash = p
                .put(&self.id, &format!("trace/{run}/{k}"), &encode_entries(&entries))
                .await?;
            chunks.push((run, k, TraceChunk { hash, entries: entries.len() }));
        }
        let bytes = {
            let mut st = lock(&self.st);
            for (run, k, c) in chunks {
                if let Some(r) = st.runs.iter_mut().find(|r| r.id == run) {
                    if r.trace_chunks.len() == k {
                        r.trace_chunks.push(c);
                    }
                }
            }
            let code = st.code.as_ref().and_then(|b| {
                lock(&b.persisted)
                    .clone()
                    .map(|parts| CodeRef { name: code_name(b), parts })
            });
            serde_json::to_vec(&SnapshotRef {
                id: &self.id,
                created_at_ms: self.created_at_ms,
                token_hashes: &self.token_hashes,
                creator: self.creator,
                versions: st.versions,
                auditor_joined: st.auditor_joined,
                questions: &st.questions,
                code,
                affidavit: &st.affidavit,
                models: &st.models,
                runs: &st.runs,
                events: st
                    .events
                    .iter()
                    .map(|e| EventRecord {
                        seqs: e.seqs,
                        at_ms: e.at_ms,
                        kind: e.kind.clone(),
                        text: e.text.clone(),
                        important: e.important,
                    })
                    .collect(),
                notify: st
                    .notify
                    .iter()
                    .map(|(r, n)| {
                        (
                            *r,
                            NotifyRecord {
                                email: n.email.clone(),
                                email_status: n.email_status.clone(),
                                changes: n.changes,
                            },
                        )
                    })
                    .collect(),
                event_counts: st.event_counts,
                disclosures: &st.disclosures,
                connections: &st.connections,
                tool_approval: st.tool_approval,
                auditor_watch: &st.auditor_watch,
            })?
        };
        let generation = lock(&self.written).0 + 1;
        let slot = generation % SLOTS;
        let parts = p.put_large(&self.id, &format!("snap/{slot}"), &bytes).await?;
        let head = serde_json::to_vec(&Head { generation, slot, parts })?;
        // Snapshots are measured as they're written: the serialized size,
        // doubled for in-memory overhead.
        let old = self.measured.swap(bytes.len() * 2, Ordering::Relaxed);
        crate::budget::remeasure(&crate::budget::STATES, old, bytes.len() * 2);
        let hash = p.put(&self.id, &format!("head/{slot}"), &head).await?;
        *lock(&self.written) = (generation, Some(format!("{slot}:{hash}")));
        Ok(())
    }
}

impl Store {
    /// Write every session that changed since it was last written.
    pub async fn write_changed(&self, p: &crate::persist::Persist) {
        let _one = self.persisting.lock().await;
        let all: Vec<Arc<Session>> = lock(&self.sessions).values().cloned().collect();
        let mut failed = 0;
        for s in all {
            if s.dirty.load(Ordering::Relaxed) && s.write_state(p).await.is_err() {
                failed += 1;
            }
        }
        if self.write_index(p, false).await.is_err() {
            failed += 1;
        }
        if failed > 0 {
            static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let now = now_ms();
            if now.saturating_sub(LAST.load(Ordering::Relaxed)) > 60_000 {
                LAST.store(now, Ordering::Relaxed);
                crate::log(&format!("state: {failed} session(s) couldn't be written; retrying"));
            }
        }
    }

    /// Write everything not yet written, and list each session's head:
    /// what a successor needs to take over. Fails rather than leave a
    /// session out.
    pub async fn write_all(&self, p: &crate::persist::Persist) -> Result<Vec<(String, String)>> {
        let _one = self.persisting.lock().await;
        let all: Vec<Arc<Session>> = lock(&self.sessions).values().cloned().collect();
        let mut heads = Vec::new();
        for s in all {
            // Everything, running runs' traces included: this is the last
            // write before the successor takes over.
            s.write_state_full(p).await?;
            if let Some(h) = lock(&s.written).1.clone() {
                heads.push((s.id.clone(), h));
            }
        }
        heads.extend(lock(&self.pending).iter().cloned());
        self.write_index(p, true).await.context("writing the session index")?;
        Ok(heads)
    }

    /// Write the session index if the set of sessions changed: those
    /// written at least once, and those still pending. Sessions are written
    /// before the index, so every session it lists has a head.
    async fn write_index(&self, p: &crate::persist::Persist, force: bool) -> Result<()> {
        let mut ids: Vec<String> = lock(&self.sessions)
            .values()
            .filter(|s| lock(&s.written).1.is_some())
            .map(|s| s.id.clone())
            .chain(lock(&self.pending).iter().map(|(sid, _)| sid.clone()))
            .collect();
        ids.sort();
        ids.dedup();
        if !force && lock(&self.index_written).as_ref() == Some(&ids) {
            return Ok(());
        }
        p.put(INDEX_SID, INDEX, &serde_json::to_vec(&ids)?).await?;
        *lock(&self.index_written) = Some(ids);
        Ok(())
    }

    /// For a promoted standby: every session in the index, each from its
    /// newest head that reads back. One that doesn't read yet waits in
    /// `pending`. Returns (sessions listed, sessions restored).
    pub async fn restore_latest(&self, ctx: &Arc<Ctx>) -> Result<(usize, usize)> {
        let ids: Vec<String> = match ctx.persist.get_any(INDEX_SID, INDEX).await? {
            Some((plain, _)) => serde_json::from_slice(&plain).context("the session index is malformed")?,
            None => Vec::new(),
        };
        let mut n = 0;
        for sid in &ids {
            match restore_newest(ctx, sid).await {
                Ok(s) => {
                    self.index_text(&s);
                    lock(&self.sessions).insert(sid.clone(), s);
                    n += 1;
                }
                Err(e) => {
                    crate::log(&format!("state: couldn't restore a session yet: {e:#}"));
                    lock(&self.pending).push((sid.clone(), String::new()));
                }
            }
        }
        Ok((ids.len(), n))
    }

    fn index_text(&self, s: &Session) {
        let st = lock(&s.st);
        let mut idx = lock(&self.text_index);
        for r in &st.runs {
            if let Some(q) = st.questions.iter().find(|q| q.version == r.question_version) {
                idx.entry(sha256_hex(q.text.as_bytes())).or_default().insert(s.id.clone());
            }
        }
    }

    /// Take over sessions from a predecessor, each from the head it named.
    /// A session that can't be read back after a few tries waits in
    /// `pending` (retried later), rather than being dropped.
    pub async fn restore(&self, ctx: &Arc<Ctx>, heads: Vec<(String, String)>) -> usize {
        let mut n = 0;
        for (sid, head) in heads {
            let mut r = restore_from(ctx, &sid, &head).await;
            for _ in 0..2 {
                if r.is_ok() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                r = restore_from(ctx, &sid, &head).await;
            }
            match r {
                Ok(s) => {
                    self.index_text(&s);
                    lock(&self.sessions).insert(sid, s);
                    n += 1;
                }
                Err(e) => {
                    crate::log(&format!("state: couldn't restore a session yet: {e:#}"));
                    lock(&self.pending).push((sid, head));
                }
            }
        }
        n
    }

    /// Try the pending sessions again. Each stays listed in `pending` until
    /// it is restored, so a standby or successor never loses sight of it.
    async fn retry_pending(&self, ctx: &Arc<Ctx>) {
        let pending = lock(&self.pending).clone();
        let mut n = 0;
        for (sid, head) in pending {
            if let Ok(s) = restore_from(ctx, &sid, &head).await {
                let mut p = lock(&self.pending);
                p.retain(|(x, h)| !(x == &sid && h == &head));
                self.index_text(&s);
                lock(&self.sessions).insert(sid, s);
                n += 1;
            }
        }
        if n > 0 {
            crate::log(&format!("state: restored {n} session(s) that were pending"));
        }
    }
}

/// Write changed sessions every couple of seconds, until this enclave
/// hands its sessions over.
pub async fn write_loop(ctx: Arc<Ctx>) {
    let mut tick: u64 = 0;
    loop {
        tokio::time::sleep(WRITE_INTERVAL).await;
        tick += 1;
        // Paused while a handoff is under way (it writes everything
        // itself), and for good once it succeeded; resumes if it failed.
        if ctx.moved.load(Ordering::SeqCst) {
            continue;
        }
        ctx.store.write_changed(&ctx.persist).await;
        if tick % 30 == 0 {
            ctx.store.retry_pending(&ctx).await;
        }
    }
}

/// A session from the head named, or with an empty head (a session from
/// the index, whose newest head isn't known), the newest that reads back.
async fn restore_from(ctx: &Arc<Ctx>, sid: &str, head: &str) -> Result<Arc<Session>> {
    if head.is_empty() {
        restore_newest(ctx, sid).await
    } else {
        restore_session(ctx, sid, head).await
    }
}

/// A session from the newest of its heads that reads back.
async fn restore_newest(ctx: &Arc<Ctx>, sid: &str) -> Result<Arc<Session>> {
    let mut heads = Vec::new();
    for slot in 0..SLOTS {
        if let Ok(Some((plain, hash))) = ctx.persist.get_any(sid, &format!("head/{slot}")).await {
            if let Ok(h) = serde_json::from_slice::<Head>(&plain) {
                if h.slot == slot {
                    heads.push((h.generation, format!("{slot}:{hash}")));
                }
            }
        }
    }
    heads.sort_by(|a, b| b.0.cmp(&a.0));
    let mut last = anyhow!("no head record reads back");
    for (_, r) in heads {
        match restore_session(ctx, sid, &r).await {
            Ok(s) => return Ok(s),
            Err(e) => last = e,
        }
    }
    Err(last)
}

async fn restore_session(ctx: &Arc<Ctx>, sid: &str, head_ref: &str) -> Result<Arc<Session>> {
    let p = &ctx.persist;
    let (slot, hash) = head_ref.split_once(':').ok_or_else(|| anyhow!("malformed head reference"))?;
    ensure!(slot.parse::<u64>().is_ok_and(|s| s < SLOTS), "malformed head slot");
    let head: Head = serde_json::from_slice(&p.get(sid, &format!("head/{slot}"), hash).await?)?;
    ensure!(head.slot.to_string() == slot, "head names another slot");
    let bytes = p
        .get_large(sid, &format!("snap/{}", head.slot), &head.parts)
        .await?;
    let snap: Snapshot = serde_json::from_slice(&bytes)?;
    ensure!(snap.id == sid, "stored state names another session");
    // Every read that can fail comes first. A Bundle deletes its stored
    // files when dropped, so it's made only once nothing else can fail:
    // otherwise a temporarily missing trace chunk would delete the code.
    let mut runs = snap.runs;
    let mut traces = Vec::with_capacity(runs.len());
    for r in &runs {
        let mut t = Trace::default();
        for (k, c) in r.trace_chunks.iter().enumerate() {
            let chunk = p.get(sid, &format!("trace/{}/{k}", r.id), &c.hash).await?;
            for e in decode_entries(&chunk)? {
                t.push_compressed(e);
            }
        }
        traces.push(t);
    }
    let manifest = match &snap.code {
        Some(c) => Some((serde_json::from_slice(&p.get_large(sid, &c.name, &c.parts).await?)?, c.parts.clone())),
        None => None,
    };
    let code = match manifest {
        Some((m, parts)) => {
            let b = Bundle::restore(sid, m, ctx.blobs.clone(), ctx.cache.clone())?;
            *lock(&b.persisted) = Some(parts);
            Some(Arc::new(b))
        }
        None => None,
    };
    for (r, t) in runs.iter_mut().zip(traces) {
        crate::budget::add(&crate::budget::TRACES, t.stored);
        r.trace = t;
    }
    let mut st = State {
        expired: false,
        versions: snap.versions,
        auditor_joined: snap.auditor_joined,
        questions: snap.questions,
        code,
        affidavit: snap.affidavit,
        models: snap.models,
        runs,
        events: snap
            .events
            .into_iter()
            .map(|e| Event {
                seqs: e.seqs,
                seq: 0,
                at_ms: e.at_ms,
                kind: e.kind,
                text: e.text,
                important: e.important,
            })
            .collect(),
        notify: snap
            .notify
            .into_iter()
            .map(|(r, n)| {
                (
                    r,
                    NotifyPrefs {
                        email: n.email,
                        email_status: n.email_status,
                        changes: n.changes,
                    },
                )
            })
            .collect(),
        event_counts: snap.event_counts,
        disclosures: snap.disclosures,
        connections: snap.connections,
        tool_approval: snap.tool_approval,
        next_connection_id: 0,
        auditor_watch: snap.auditor_watch,
        disclosures_in_flight: 0,
    };
    // Runs that were going when the state was written can't continue here:
    // record them as failed. The auditee decides on them as usual.
    let now = now_ms();
    let mut interrupted = Vec::new();
    for r in st.runs.iter_mut() {
        r.before_move = true;
    }
    for r in st.runs.iter_mut().filter(|r| r.status == "running") {
        let outcome = Outcome::Error {
            message: INTERRUPTED.into(),
        };
        if let Some(mut m) = r.template.clone() {
            m.started_at_ms = r.started_at_ms;
            m.finished_at_ms = now;
            m.outcome = outcome.clone();
            r.full = Some(CertificateBody {
                manifest: m,
                verdict: None,
            });
        }
        r.status = "awaiting_release";
        r.finished_at_ms = Some(now);
        r.verdict = None;
        r.outcome = Some(outcome);
        interrupted.push(r.number);
    }
    let s = Arc::new(Session {
        id: snap.id,
        created_at_ms: snap.created_at_ms,
        token_hashes: snap.token_hashes,
        creator: snap.creator,
        tx: [
            watch::channel(st.versions[0]).0,
            watch::channel(st.versions[1]).0,
        ],
        st: Mutex::new(State::default()),
        dirty: AtomicBool::new(false),
        written: Mutex::new((head.generation, Some(head_ref.to_string()))),
        measured: (bytes.len() * 2).into(),
        approvals: Default::default(),
    });
    crate::budget::add(&crate::budget::STATES, bytes.len() * 2);
    {
        let mut guard = lock(&s.st);
        *guard = st;
        for n in interrupted {
            s.event(
                ctx,
                &mut guard,
                "run_finished",
                format!("Run {n} was interrupted when the enclave restarted or moved. Review it and decide whether to release it."),
                Some(Role::Auditee),
                None,
                false,
            );
        }
        // Clients that followed the session here look again.
        s.changed(&mut guard);
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_chunks_round_trip() {
        let e = vec![b"one".to_vec(), vec![], vec![7u8; 1000]];
        assert_eq!(decode_entries(&encode_entries(&e)).unwrap(), e);
        let mut bad = encode_entries(&e);
        bad.pop();
        assert!(decode_entries(&bad).is_err());
    }
}
