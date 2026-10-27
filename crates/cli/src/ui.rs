//! `attest ui`: a local web app over a workspace directory.
//!
//! Binds 127.0.0.1 only. Requests must carry a localhost Host header (blocks
//! DNS rebinding) and POSTs must carry `x-attest: 1` (a custom header forces a
//! CORS preflight, which this server never answers, so other sites cannot
//! drive it).
//!
//! Workspace layout:
//!   settings.json
//!   keys/{auditor,auditee}.json
//!   questions/<question id>.json         signed questions, own and imported
//!   runs/<run id>/{meta,certificate,trace}.json
//!   received/<run id>.json               certificates the auditor verified

use crate::ops::{self, read_json, write_json, Keys};
use anyhow::{anyhow, bail, Context, Result};
use attest_core::nitro::ExpectedPcrs;
use attest_core::verify::EnclavePolicy;
use attest_core::*;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const INDEX_HTML: &str = include_str!("ui/index.html");

#[derive(Serialize, Deserialize, Clone, Default)]
struct Settings {
    enclave: String,
    pcrs_path: Option<String>,
    allow_dev: bool,
    skip_measurement: bool,
    /// Form defaults remembered between sessions (never the API key).
    #[serde(default)]
    last: Value,
}

#[derive(Serialize, Deserialize, Clone)]
struct RunMeta {
    run_id: String,
    enclave: String,
    enclave_info_json: String,
    question_id: String,
    question_text: String,
    org: String,
    provider: Provider,
    model: String,
    file_count: usize,
    tree: String,
    submitted_at_ms: u64,
    /// running | done | failed | lost
    status: String,
    steps: u32,
    error: Option<String>,
    verdict: Option<Verdict>,
}

struct App {
    ws: PathBuf,
    port: u16,
    settings: Mutex<Settings>,
    watching: Mutex<HashSet<String>>,
    write_lock: Mutex<()>,
}

pub fn run(ws: PathBuf, port: u16, enclave: Option<String>, open: bool) -> Result<()> {
    std::fs::create_dir_all(&ws)?;
    let ws = ws.canonicalize()?;
    let mut settings: Settings = read_json(&ws.join("settings.json")).unwrap_or_default();
    if let Some(e) = enclave {
        settings.enclave = e;
    }
    let app = Arc::new(App {
        ws,
        port,
        settings: Mutex::new(settings),
        watching: Mutex::new(HashSet::new()),
        write_lock: Mutex::new(()),
    });
    app.save_settings()?;
    // Resume following runs that were in flight when the app last stopped.
    for meta in app.list_runs() {
        if meta.status == "running" {
            app.clone().watch(meta.run_id.clone());
        }
    }
    let url = format!("http://127.0.0.1:{port}/");
    println!("attest ui: {url}  (workspace {})", app.ws.display());
    if open {
        let _ = std::process::Command::new("open").arg(&url).spawn();
    }
    tokio::runtime::Builder::new_multi_thread().enable_all().build()?.block_on(serve(app))
}

async fn serve(app: Arc<App>) -> Result<()> {
    let l = tokio::net::TcpListener::bind(("127.0.0.1", app.port)).await.context("binding UI port")?;
    loop {
        let (s, _) = l.accept().await?;
        let app = app.clone();
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |req| {
                let app = app.clone();
                async move { Ok::<_, std::convert::Infallible>(handle(app, req).await) }
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(s), svc).await;
        });
    }
}

fn respond(status: StatusCode, ctype: &str, body: Vec<u8>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", ctype)
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff")
        .header("referrer-policy", "no-referrer")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

fn json_ok(v: Value) -> Response<Full<Bytes>> {
    respond(StatusCode::OK, "application/json", serde_json::to_vec(&v).unwrap_or_default())
}

async fn handle(app: Arc<App>, req: Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
    let host = req.headers().get("host").and_then(|h| h.to_str().ok()).unwrap_or("");
    let ok_hosts = [format!("127.0.0.1:{}", app.port), format!("localhost:{}", app.port)];
    if !ok_hosts.iter().any(|h| h == host) {
        return respond(StatusCode::FORBIDDEN, "text/plain", b"bad host".to_vec());
    }
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    if method == hyper::Method::GET && (path == "/" || path == "/index.html") {
        return respond(StatusCode::OK, "text/html; charset=utf-8", INDEX_HTML.as_bytes().to_vec());
    }
    if method == hyper::Method::POST && req.headers().get("x-attest").map(|v| v.as_bytes()) != Some(b"1") {
        return respond(StatusCode::FORBIDDEN, "text/plain", b"missing x-attest header".to_vec());
    }
    let body = match http_body_util::Limited::new(req.into_body(), 64 << 20).collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => return respond(StatusCode::PAYLOAD_TOO_LARGE, "text/plain", b"too large".to_vec()),
    };
    let input: Value = if body.is_empty() { Value::Null } else { serde_json::from_slice(&body).unwrap_or(Value::Null) };
    let m = method.as_str().to_string();
    // Everything below may do blocking IO (hashing repos, network).
    let r = tokio::task::spawn_blocking(move || route(&app, &m, &path, input)).await;
    match r {
        Ok(Ok(Reply::Json(v))) => json_ok(v),
        Ok(Ok(Reply::Download(name, bytes))) => {
            let mut resp = respond(StatusCode::OK, "application/json", bytes);
            resp.headers_mut().insert(
                "content-disposition",
                format!("attachment; filename=\"{name}\"").parse().unwrap(),
            );
            resp
        }
        Ok(Err(e)) => respond(
            StatusCode::BAD_REQUEST,
            "application/json",
            serde_json::to_vec(&json!({"error": format!("{e:#}")})).unwrap_or_default(),
        ),
        Err(_) => respond(StatusCode::INTERNAL_SERVER_ERROR, "text/plain", b"internal error".to_vec()),
    }
}

enum Reply {
    Json(Value),
    Download(String, Vec<u8>),
}

fn s(v: &Value, k: &str) -> Option<String> {
    v[k].as_str().map(|x| x.trim().to_string()).filter(|x| !x.is_empty())
}

fn safe_id(id: &str) -> Result<&str> {
    if id.is_empty() || id.len() > 128 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("bad id");
    }
    Ok(id)
}

fn route(app: &Arc<App>, method: &str, path: &str, input: Value) -> Result<Reply> {
    let parts: Vec<&str> = path.trim_start_matches("/api/").split('/').collect();
    Ok(Reply::Json(match (method, parts.as_slice()) {
        ("GET", ["state"]) => app.state()?,
        ("POST", ["settings"]) => app.update_settings(&input)?,
        ("POST", ["keys"]) => app.create_key(&input)?,
        ("POST", ["enclave"]) => {
            let st = app.settings.lock().unwrap().clone();
            if st.enclave.is_empty() {
                bail!("set the enclave URL first");
            }
            let v = ops::attest_enclave(&st.enclave, &app.policy()?)?;
            ops::enclave_json(&v)
        }
        ("POST", ["questions"]) => app.new_question(&input)?,
        ("POST", ["questions", "import"]) => app.import_question(&input)?,
        ("GET", ["questions", id, "download"]) => {
            let id = safe_id(id)?;
            let bytes = std::fs::read(app.ws.join("questions").join(format!("{id}.json")))?;
            return Ok(Reply::Download(format!("question-{}.json", &id[..12]), bytes));
        }
        ("POST", ["questions", id, "log"]) => {
            let q = app.question(safe_id(id)?)?;
            let st = app.settings.lock().unwrap().clone();
            let (v, log) = ops::fetch_log(&st.enclave, &app.policy()?, ops::LogQuery::Question(&q))?;
            json!({"enclave": ops::enclave_json(&v), "log": log})
        }
        ("POST", ["inspect"]) => {
            let dir = expand(&s(&input, "dir").ok_or_else(|| anyhow!("choose a directory"))?);
            let p = ops::prepare(&dir)?;
            json!({
                "dir": dir, "file_count": p.file_count, "total_bytes": p.total_bytes, "tree": p.tree,
                "git": {"is_repo": p.git.is_repo, "head": p.git.head, "remote": p.git.remote, "dirty": p.git.dirty},
            })
        }
        ("POST", ["statement"]) => json!({"statement": ops::affidavit_statement(
            &s(&input, "org").unwrap_or_else(|| "(organization)".into()),
            &s(&input, "tree").unwrap_or_default(),
            s(&input, "repo_url").as_deref(),
            s(&input, "git_commit").as_deref(),
        )}),
        ("POST", ["submit"]) => app.submit(&input)?,
        ("GET", ["runs", id]) => app.run_detail(safe_id(id)?)?,
        ("GET", ["runs", id, "certificate"]) => {
            let id = safe_id(id)?;
            let bytes = std::fs::read(app.ws.join("runs").join(id).join("certificate.json"))
                .context("this run has no certificate yet")?;
            return Ok(Reply::Download(format!("certificate-{}.json", &id[..12]), bytes));
        }
        ("POST", ["verify"]) => app.verify(&input)?,
        ("GET", ["received", id]) => app.received(safe_id(id)?)?,
        _ => bail!("not found: {method} {path}"),
    }))
}

fn expand(p: &str) -> PathBuf {
    match p.strip_prefix("~/") {
        Some(rest) => std::env::var("HOME").map(|h| PathBuf::from(h).join(rest)).unwrap_or_else(|_| PathBuf::from(p)),
        None => PathBuf::from(p),
    }
}

impl App {
    fn save_settings(&self) -> Result<()> {
        write_json(&self.ws.join("settings.json"), &*self.settings.lock().unwrap())
    }

    fn policy(&self) -> Result<EnclavePolicy> {
        let st = self.settings.lock().unwrap().clone();
        let expected = match st.pcrs_path.as_deref().filter(|p| !p.is_empty()) {
            Some(p) => Some(ExpectedPcrs::from_json(
                &std::fs::read_to_string(expand(p)).with_context(|| format!("reading measurements file {p}"))?,
            )?),
            None => None,
        };
        Ok(EnclavePolicy { expected, allow_dev: st.allow_dev, skip_measurement: st.skip_measurement })
    }

    fn key_path(&self, role: &str) -> PathBuf {
        self.ws.join("keys").join(format!("{role}.json"))
    }

    fn key(&self, role: &str) -> Result<Keys> {
        ops::load_key(&self.key_path(role)).map_err(|_| anyhow!("create your {role} key first"))
    }

    fn question(&self, id: &str) -> Result<Signed> {
        read_json(&self.ws.join("questions").join(format!("{id}.json"))).map_err(|_| anyhow!("unknown question"))
    }

    fn list_runs(&self) -> Vec<RunMeta> {
        let mut v: Vec<RunMeta> = std::fs::read_dir(self.ws.join("runs"))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| read_json(&e.path().join("meta.json")).ok())
            .collect();
        v.sort_by(|a, b| b.submitted_at_ms.cmp(&a.submitted_at_ms));
        v
    }

    fn state(&self) -> Result<Value> {
        let st = self.settings.lock().unwrap().clone();
        let pk = |role| self.key(role).ok().map(|k| k.file.public_key);
        let auditor = pk("auditor");
        let mut questions = Vec::new();
        for e in std::fs::read_dir(self.ws.join("questions")).into_iter().flatten().flatten() {
            let Ok(sq) = read_json::<Signed>(&e.path()) else { continue };
            let Ok(body) = sq.open::<QuestionBody>(DOMAIN_QUESTION) else { continue };
            questions.push(json!({
                "id": sq.id(),
                "text": body.text,
                "created_at_ms": body.created_at_ms,
                "policy": body.policy,
                "auditor_key": sq.public_key,
                "mine": auditor.as_deref() == Some(sq.public_key.as_str()),
            }));
        }
        questions.sort_by(|a, b| b["created_at_ms"].as_u64().cmp(&a["created_at_ms"].as_u64()));
        let mut received = Vec::new();
        for e in std::fs::read_dir(self.ws.join("received")).into_iter().flatten().flatten() {
            if let Ok(v) = read_json::<Value>(&e.path()) {
                received.push(v["summary"].clone());
            }
        }
        received.sort_by(|a, b| b["verified_at_ms"].as_u64().cmp(&a["verified_at_ms"].as_u64()));
        Ok(json!({
            "workspace": self.ws,
            "settings": st,
            "keys": {"auditor": auditor, "auditee": pk("auditee")},
            "questions": questions,
            "runs": self.list_runs(),
            "received": received,
        }))
    }

    fn update_settings(&self, v: &Value) -> Result<Value> {
        {
            let mut st = self.settings.lock().unwrap();
            if let Some(e) = v.get("enclave").and_then(|x| x.as_str()) {
                st.enclave = e.trim().to_string();
            }
            if let Some(p) = v.get("pcrs_path") {
                st.pcrs_path = p.as_str().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
            }
            if let Some(b) = v["allow_dev"].as_bool() {
                st.allow_dev = b;
            }
            if let Some(b) = v["skip_measurement"].as_bool() {
                st.skip_measurement = b;
            }
            if v.get("last").is_some() {
                st.last = v["last"].clone();
            }
        }
        self.save_settings()?;
        self.policy()?; // surface a bad measurements file right away
        Ok(json!({"ok": true}))
    }

    fn create_key(&self, v: &Value) -> Result<Value> {
        let role = s(v, "role").unwrap_or_default();
        if role != "auditor" && role != "auditee" {
            bail!("role must be auditor or auditee");
        }
        let kf = ops::generate_key(&self.key_path(&role))?;
        Ok(json!({"public_key": kf.public_key}))
    }

    fn new_question(&self, v: &Value) -> Result<Value> {
        let keys = self.key("auditor")?;
        let q = ops::make_question(
            &keys,
            &s(v, "text").unwrap_or_default(),
            v["allow_fine_tuned"].as_bool().unwrap_or(false),
            v["max_steps"].as_u64().unwrap_or(150).clamp(1, 400) as u32,
        )?;
        write_json(&self.ws.join("questions").join(format!("{}.json", q.id())), &q)?;
        Ok(json!({"id": q.id()}))
    }

    fn import_question(&self, v: &Value) -> Result<Value> {
        let q: Signed = serde_json::from_value(v["question"].clone()).context("that is not a question file")?;
        q.open::<QuestionBody>(DOMAIN_QUESTION).context("question signature does not verify")?;
        write_json(&self.ws.join("questions").join(format!("{}.json", q.id())), &q)?;
        Ok(json!({"id": q.id()}))
    }

    fn submit(self: &Arc<Self>, v: &Value) -> Result<Value> {
        let keys = self.key("auditee")?;
        let qid = s(v, "question_id").ok_or_else(|| anyhow!("choose a question"))?;
        let question = self.question(safe_id(&qid)?)?;
        let qbody: QuestionBody = question.open(DOMAIN_QUESTION)?;
        let dir = expand(&s(v, "dir").ok_or_else(|| anyhow!("choose the repository directory"))?);
        let provider: Provider = s(v, "provider").unwrap_or_default().parse()?;
        let model = s(v, "model").ok_or_else(|| anyhow!("enter a model"))?;
        let api_key = s(v, "api_key").ok_or_else(|| anyhow!("enter the API key"))?;
        let org = s(v, "org").ok_or_else(|| anyhow!("enter your organization"))?;
        if !v["sign"].as_bool().unwrap_or(false) {
            bail!("confirm the affidavit first");
        }
        let prepared = ops::prepare(&dir)?;
        // The affidavit the user read named a tree hash; refuse to sign another.
        if s(v, "expected_tree").as_deref() != Some(prepared.tree.as_str()) {
            bail!("the repository changed since you inspected it; inspect it again and re-read the affidavit");
        }
        if prepared.git.dirty && !v["allow_dirty"].as_bool().unwrap_or(false) {
            bail!("the repository has uncommitted changes to tracked files");
        }
        let st = self.settings.lock().unwrap().clone();
        if st.enclave.is_empty() {
            bail!("set the enclave URL in Settings");
        }
        let enclave_v = ops::attest_enclave(&st.enclave, &self.policy()?)?;
        let (file_count, tree) = (prepared.file_count, prepared.tree.clone());
        let run_id = ops::submit(ops::SubmitArgs {
            enclave: &st.enclave,
            enclave_v: &enclave_v,
            keys: &keys,
            question: &question,
            prepared,
            org: org.clone(),
            provider,
            model: model.clone(),
            api_key,
            repo_url: s(v, "repo_url"),
            git_commit: s(v, "git_commit"),
            zdr: v["zdr"].as_bool().unwrap_or(false),
            mock_endpoint: s(v, "mock_endpoint"),
        })?;
        let meta = RunMeta {
            run_id: run_id.clone(),
            enclave: st.enclave.clone(),
            enclave_info_json: serde_json::to_string(&enclave_v.info)?,
            question_id: qid,
            question_text: qbody.text,
            org,
            provider,
            model,
            file_count,
            tree,
            submitted_at_ms: now_ms(),
            status: "running".into(),
            steps: 0,
            error: None,
            verdict: None,
        };
        self.save_meta(&meta)?;
        self.clone().watch(run_id.clone());
        Ok(json!({"run_id": run_id}))
    }

    fn run_dir(&self, id: &str) -> PathBuf {
        self.ws.join("runs").join(id)
    }

    fn save_meta(&self, m: &RunMeta) -> Result<()> {
        let _g = self.write_lock.lock().unwrap();
        write_json(&self.run_dir(&m.run_id).join("meta.json"), m)
    }

    /// Follow a run in the background until it finishes.
    fn watch(self: Arc<Self>, id: String) {
        if !self.watching.lock().unwrap().insert(id.clone()) {
            return;
        }
        std::thread::spawn(move || {
            let mut failures = 0;
            loop {
                let Ok(mut meta) = read_json::<RunMeta>(&self.run_dir(&id).join("meta.json")) else { break };
                match ops::poll(&meta.enclave, &id) {
                    Ok(status) => {
                        failures = 0;
                        meta.steps = status.steps;
                        if status.result_age_b64.is_some() {
                            match self.store_result(&mut meta, &status) {
                                Ok(()) => {}
                                Err(e) => {
                                    meta.status = "failed".into();
                                    meta.error = Some(format!("{e:#}"));
                                }
                            }
                            let _ = self.save_meta(&meta);
                            break;
                        }
                        if status.status == RunStatus::Failed {
                            meta.status = "failed".into();
                            meta.error = Some("the enclave could not finish this run".into());
                            let _ = self.save_meta(&meta);
                            break;
                        }
                        let _ = self.save_meta(&meta);
                    }
                    Err(e) => {
                        let msg = format!("{e:#}");
                        // The enclave forgets runs when it restarts.
                        if msg.contains("HTTP 404") {
                            meta.status = "lost".into();
                            meta.error = Some("the enclave restarted and this run was lost".into());
                            let _ = self.save_meta(&meta);
                            break;
                        }
                        failures += 1;
                        meta.error = Some(format!("cannot reach the enclave (retrying): {msg}"));
                        let _ = self.save_meta(&meta);
                    }
                }
                std::thread::sleep(Duration::from_secs(if failures > 0 { 10 } else { 2 }));
            }
            self.watching.lock().unwrap().remove(&id);
        });
    }

    fn store_result(&self, meta: &mut RunMeta, status: &RunStatusResponse) -> Result<()> {
        let keys = self.key("auditee")?;
        let result = ops::open_result(status, &keys, Some(&meta.enclave_info_json))?;
        let body: CertificateBody = serde_json::from_str(&result.certificate.signed.body)?;
        let dir = self.run_dir(&meta.run_id);
        write_json(&dir.join("certificate.json"), &result.certificate)?;
        write_json(&dir.join("trace.json"), &result.trace)?;
        meta.verdict = body.verdict.clone();
        meta.error = match &body.manifest.outcome {
            Outcome::Error { message } => Some(message.clone()),
            Outcome::StepLimit => Some("the model hit the step limit before answering".into()),
            Outcome::Completed => None,
        };
        meta.status = if body.verdict.is_some() { "done" } else { "failed" }.into();
        Ok(())
    }

    fn run_detail(&self, id: &str) -> Result<Value> {
        let dir = self.run_dir(id);
        let meta: RunMeta = read_json(&dir.join("meta.json")).map_err(|_| anyhow!("unknown run"))?;
        let mut out = json!({"meta": meta});
        if let Ok(cert) = read_json::<Certificate>(&dir.join("certificate.json")) {
            // Use the configured policy when it accepts; otherwise fall back to
            // a lenient one (the warnings then say what was not checked).
            let report = self
                .policy()
                .and_then(|p| ops::verify(&cert, &p, None))
                .or_else(|_| ops::verify(&cert, &EnclavePolicy { expected: None, allow_dev: true, skip_measurement: true }, None));
            match report {
                Ok(v) => out["report"] = ops::report_json(&v),
                Err(e) => out["report_error"] = json!(format!("{e:#}")),
            }
            out["trace"] = read_json::<Value>(&dir.join("trace.json")).unwrap_or(Value::Null);
        }
        Ok(out)
    }

    /// Re-verify a stored certificate (settings may have changed since).
    fn received(&self, id: &str) -> Result<Value> {
        let stored: Value = read_json(&self.ws.join("received").join(format!("{id}.json")))?;
        let mut input = json!({"certificate": stored["certificate"]});
        if stored["summary"]["matched_question"].as_bool() == Some(true) {
            input["question_id"] = stored["summary"]["question_id"].clone();
        }
        self.verify(&input)
    }

    fn verify(&self, v: &Value) -> Result<Value> {
        let cert: Certificate =
            serde_json::from_value(v["certificate"].clone()).context("that is not an attest certificate file")?;
        let question = match s(v, "question_id") {
            Some(id) => Some(self.question(safe_id(&id)?)?),
            None => None,
        };
        let verified = ops::verify(&cert, &self.policy()?, question.as_ref())?;
        let report = ops::report_json(&verified);
        let m = &verified.body.manifest;
        let summary = json!({
            "run_id": m.run_id,
            "question_id": m.question_id,
            "question_text": verified.question.text,
            "org": verified.affidavit.organization,
            "answer": verified.body.verdict.as_ref().map(|v| v.answer),
            "matched_question": question.is_some(),
            "warning_count": report["warnings"].as_array().map(|a| a.len()).unwrap_or(0),
            "verified_at_ms": now_ms(),
        });
        write_json(
            &self.ws.join("received").join(format!("{}.json", safe_id(&m.run_id)?)),
            &json!({"summary": summary, "certificate": cert}),
        )?;
        Ok(json!({"report": report, "summary": summary}))
    }
}
