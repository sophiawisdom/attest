//! attest enclave: runs a read-only LLM audit over code it never discloses,
//! and signs a manifest of what the auditee chose.
//!
//! HTTP API (served over vsock, forwarded by the untrusted host):
//!   GET  /v1/attestation[?nonce=hex]   enclave info + attestation documents
//!   POST /v1/runs                      age-encrypted submission -> run id
//!   GET  /v1/runs/{id}                 status; result encrypted to the auditee
//!   GET  /v1/log?question_text_sha256=..|auditee=..   signed run log

mod bundle;
mod llm;
mod net;
mod nsm;
mod run;

use anyhow::{anyhow, bail, Context, Result};
use attest_core::harness::{self, HARNESS_VERSION, MAX_STEPS_CAP, TOOLS};
use attest_core::*;
use base64::Engine;
use bytes::Bytes;
use clap::Parser;
use ed25519_dalek::SigningKey;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

const LISTEN_VSOCK_PORT: u32 = 5000;

#[derive(Parser, Debug)]
#[command(name = "attest-enclave")]
struct Args {
    /// Local development: TCP instead of vsock, no attestation, mock provider allowed.
    #[arg(long)]
    dev: bool,
    /// Dev only: address to listen on.
    #[arg(long, default_value = "127.0.0.1:5000")]
    dev_listen: String,
    /// Dev only: address of the host's CONNECT tunnel.
    #[arg(long, default_value = "127.0.0.1:5001")]
    dev_tunnel: String,
    /// Largest accepted (encrypted) submission.
    #[arg(long, default_value_t = 1 << 30)]
    max_submission_bytes: usize,
    /// Audits running at once.
    #[arg(long, default_value_t = 4)]
    concurrency: usize,
}

struct RunRecord {
    status: RunStatus,
    steps: Arc<AtomicU32>,
    result_age_b64: Option<String>,
}

struct State {
    dev: bool,
    info: EnclaveInfo,
    info_json: String,
    boot_doc_b64: Option<String>,
    signing: SigningKey,
    age_identity: age::x25519::Identity,
    attester: nsm::Attester,
    net: net::Net,
    runs: Mutex<HashMap<String, RunRecord>>,
    log: Mutex<Vec<RunLogEntry>>,
    slots: tokio::sync::Semaphore,
    max_submission_bytes: usize,
}

fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    hex::encode(b)
}

fn log(msg: &str) {
    eprintln!("[attest-enclave] {msg}");
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let attester = nsm::Attester::new(args.dev)?;
    // Inside Nitro the kernel RNG is fed by the NSM hardware RNG.
    let signing = SigningKey::generate(&mut rand::rngs::OsRng);
    let age_identity = age::x25519::Identity::generate();

    let mut endpoints = BTreeMap::new();
    for p in [Provider::Openai, Provider::Anthropic, Provider::Openrouter] {
        let (h, path) = llm::endpoint(p);
        endpoints.insert(p.as_str().to_string(), format!("https://{h}{path}"));
    }
    let info = EnclaveInfo {
        service: "attest".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        mode: if args.dev { "dev" } else { "nitro" }.into(),
        boot_id: random_hex(16),
        booted_at_ms: now_ms(),
        signing_public_key: hex::encode(signing.verifying_key().to_bytes()),
        age_recipient: age_identity.to_public().to_string(),
        harness: HarnessInfo {
            version: HARNESS_VERSION.into(),
            system_prompt_sha256: harness::system_prompt_sha256(),
            tools: TOOLS.iter().map(|s| s.to_string()).collect(),
            max_steps_cap: MAX_STEPS_CAP,
            endpoints,
        },
    };
    let info_json = serde_json::to_string(&info)?;
    let boot_doc = attester.attest(&sha256(info_json.as_bytes()), &signing.verifying_key().to_bytes(), None)?;
    let b64 = base64::engine::general_purpose::STANDARD;

    let state = Arc::new(State {
        dev: args.dev,
        boot_doc_b64: boot_doc.map(|d| b64.encode(d)),
        info,
        info_json,
        signing,
        age_identity,
        attester,
        net: net::Net::new(args.dev, args.dev_tunnel.clone())?,
        runs: Mutex::new(HashMap::new()),
        log: Mutex::new(Vec::new()),
        slots: tokio::sync::Semaphore::new(args.concurrency),
        max_submission_bytes: args.max_submission_bytes,
    });
    log(&format!("boot {} mode={} key={}", state.info.boot_id, state.info.mode, state.info.signing_public_key));
    serve(args, state).await
}

async fn serve(args: Args, state: Arc<State>) -> Result<()> {
    macro_rules! spawn_conn {
        ($io:expr) => {{
            let st = state.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req| {
                    let st = st.clone();
                    async move { Ok::<_, std::convert::Infallible>(handle(st, req).await) }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new($io), svc).await;
            });
        }};
    }
    if args.dev {
        let l = tokio::net::TcpListener::bind(&args.dev_listen).await?;
        log(&format!("dev: listening on {}", args.dev_listen));
        loop {
            let (s, _) = l.accept().await?;
            spawn_conn!(s);
        }
    }
    #[cfg(target_os = "linux")]
    {
        let l = tokio_vsock::VsockListener::bind(tokio_vsock::VsockAddr::new(tokio_vsock::VMADDR_CID_ANY, LISTEN_VSOCK_PORT))
            .context("binding vsock")?;
        log(&format!("listening on vsock port {LISTEN_VSOCK_PORT}"));
        loop {
            let (s, _) = l.accept().await?;
            spawn_conn!(s);
        }
    }
    #[allow(unreachable_code)]
    {
        let _ = LISTEN_VSOCK_PORT;
        bail!("vsock requires linux; run with --dev")
    }
}

fn json_response<T: serde::Serialize>(status: StatusCode, v: &T) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(Full::new(Bytes::from(serde_json::to_vec(v).unwrap_or_default())))
        .unwrap()
}

fn error(status: StatusCode, msg: impl std::fmt::Display) -> Response<Full<Bytes>> {
    json_response(status, &serde_json::json!({"error": msg.to_string()}))
}

fn query(req: &Request<hyper::body::Incoming>) -> HashMap<String, String> {
    req.uri()
        .query()
        .map(|q| url::form_urlencoded::parse(q.as_bytes()).into_owned().collect())
        .unwrap_or_default()
}

async fn handle(st: Arc<State>, req: Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    let r = match (method.as_str(), path.as_str()) {
        ("GET", "/healthz") => Ok(json_response(StatusCode::OK, &serde_json::json!({"ok": true}))),
        ("GET", "/v1/attestation") => attestation(&st, &query(&req)),
        ("POST", "/v1/runs") => submit(st.clone(), req).await,
        ("GET", "/v1/log") => run_log(&st, &query(&req)),
        ("GET", p) if p.starts_with("/v1/runs/") => run_status(&st, &p["/v1/runs/".len()..]),
        _ => Ok(error(StatusCode::NOT_FOUND, "not found")),
    };
    r.unwrap_or_else(|e| error(StatusCode::BAD_REQUEST, format!("{e:#}")))
}

fn attestation(st: &State, q: &HashMap<String, String>) -> Result<Response<Full<Bytes>>> {
    let fresh = match q.get("nonce") {
        Some(n) => {
            let nonce = hex::decode(n).context("nonce must be hex")?;
            if nonce.len() > 64 {
                bail!("nonce too long");
            }
            st.attester
                .attest(&sha256(st.info_json.as_bytes()), &st.signing.verifying_key().to_bytes(), Some(&nonce))?
                .map(|d| base64::engine::general_purpose::STANDARD.encode(d))
        }
        None => None,
    };
    Ok(json_response(
        StatusCode::OK,
        &AttestationResponse {
            enclave_info_json: st.info_json.clone(),
            boot_document_b64: st.boot_doc_b64.clone(),
            fresh_document_b64: fresh,
        },
    ))
}

async fn submit(st: Arc<State>, req: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>> {
    let submitted_at_ms = now_ms();
    let body = http_body_util::Limited::new(req.into_body(), st.max_submission_bytes)
        .collect()
        .await
        .map_err(|e| anyhow!("reading submission: {e}"))?
        .to_bytes();
    let plain = age::decrypt(&st.age_identity, &body).map_err(|_| anyhow!("submission is not encrypted to this enclave boot"))?;
    drop(body);
    let (header, tar) = split_submission(&plain)?;

    // Question and affidavit must be signed, and the affidavit must bind this
    // exact question and code.
    let question_body: QuestionBody = header.question.open(DOMAIN_QUESTION)?;
    let affidavit_body: AffidavitBody = header.affidavit.open(DOMAIN_AFFIDAVIT)?;
    let question_id = header.question.id();
    if affidavit_body.question_id != question_id {
        bail!("affidavit names a different question");
    }
    if header.provider == Provider::Mock && !st.dev {
        bail!("mock provider is only available in dev mode");
    }
    if llm::is_fine_tuned(header.provider, &header.model) && !question_body.policy.allow_fine_tuned {
        bail!("the auditor's question does not allow fine-tuned models");
    }
    if header.model.trim().is_empty() || header.api_key.trim().is_empty() {
        bail!("model and api_key are required");
    }
    let reply_to: age::x25519::Recipient = header.reply_recipient.parse().map_err(|e| anyhow!("reply recipient: {e}"))?;
    let bundle = bundle::Bundle::from_tar(tar)?;
    if bundle.info.tree_sha256 != affidavit_body.code_tree_sha256 {
        bail!("code bundle does not match the tree hash in the affidavit");
    }
    let client = llm::Client::new(
        st.net.clone(),
        header.provider,
        header.model.clone(),
        header.api_key.clone(),
        header.openrouter_zdr,
        header.mock_endpoint.clone(),
    )?;
    drop(plain);

    // Record the run before it starts: it counts even if it never finishes.
    let run_id = random_hex(16);
    let question_text_sha256 = sha256_hex(question_body.text.as_bytes());
    let auditee = header.affidavit.public_key.clone();
    let history = {
        let mut log = st.log.lock().unwrap();
        let same_text: Vec<&RunLogEntry> = log.iter().filter(|e| e.question_text_sha256 == question_text_sha256).collect();
        let mut hashes: Vec<String> = same_text.iter().map(|e| e.code_tree_sha256.clone()).collect();
        hashes.sort();
        hashes.dedup();
        let h = History {
            prior_runs_same_question_text: same_text.len() as u64,
            prior_runs_same_question_id: log.iter().filter(|e| e.question_id == question_id).count() as u64,
            prior_runs_same_auditee: log.iter().filter(|e| e.auditee_public_key == auditee).count() as u64,
            prior_code_hashes_same_question_text: hashes,
        };
        log.push(RunLogEntry {
            run_id: run_id.clone(),
            submitted_at_ms,
            question_id: question_id.clone(),
            question_text_sha256,
            auditee_public_key: auditee,
            code_tree_sha256: bundle.info.tree_sha256.clone(),
            provider: header.provider,
            model: header.model.clone(),
            status: RunStatus::Queued,
        });
        h
    };
    let steps = Arc::new(AtomicU32::new(0));
    st.runs.lock().unwrap().insert(
        run_id.clone(),
        RunRecord { status: RunStatus::Queued, steps: steps.clone(), result_age_b64: None },
    );
    log(&format!("run {run_id}: queued ({} files, provider {})", bundle.info.file_count, header.provider.as_str()));

    let input = run::RunInput {
        run_id: run_id.clone(),
        boot_id: st.info.boot_id.clone(),
        harness: st.info.harness.clone(),
        submitted_at_ms,
        question: header.question.clone(),
        question_body,
        affidavit: header.affidavit.clone(),
        bundle,
        client,
        history,
    };
    let st2 = st.clone();
    let id2 = run_id.clone();
    tokio::spawn(async move {
        let _permit = st2.slots.acquire().await;
        set_status(&st2, &id2, RunStatus::Running, None);
        let (body, trace) = run::execute(input, steps).await;
        let failed = matches!(body.manifest.outcome, Outcome::Error { .. });
        let result = (|| -> Result<String> {
            let signed = sign::sign(&st2.signing, DOMAIN_CERTIFICATE, &body)?;
            let certificate = Certificate {
                enclave_info_json: st2.info_json.clone(),
                boot_document_b64: st2.boot_doc_b64.clone(),
                signed,
            };
            let plain = serde_json::to_vec(&RunResult { certificate, trace })?;
            let ct = age::encrypt(&reply_to, &plain)?;
            Ok(base64::engine::general_purpose::STANDARD.encode(ct))
        })();
        match result {
            Ok(r) => {
                let status = if failed { RunStatus::Failed } else { RunStatus::Done };
                log(&format!("run {id2}: {status:?}"));
                set_status(&st2, &id2, status, Some(r));
            }
            Err(e) => {
                log(&format!("run {id2}: could not seal result: {e:#}"));
                set_status(&st2, &id2, RunStatus::Failed, None);
            }
        }
    });
    Ok(json_response(StatusCode::OK, &SubmitResponse { run_id }))
}

fn set_status(st: &State, id: &str, status: RunStatus, result: Option<String>) {
    if let Some(r) = st.runs.lock().unwrap().get_mut(id) {
        r.status = status.clone();
        if result.is_some() {
            r.result_age_b64 = result;
        }
    }
    if let Some(e) = st.log.lock().unwrap().iter_mut().find(|e| e.run_id == id) {
        e.status = status;
    }
}

fn run_status(st: &State, id: &str) -> Result<Response<Full<Bytes>>> {
    let runs = st.runs.lock().unwrap();
    let Some(r) = runs.get(id) else {
        return Ok(error(StatusCode::NOT_FOUND, "no such run"));
    };
    Ok(json_response(
        StatusCode::OK,
        &RunStatusResponse {
            run_id: id.to_string(),
            status: r.status.clone(),
            steps: r.steps.load(Ordering::Relaxed),
            result_age_b64: r.result_age_b64.clone(),
        },
    ))
}

fn run_log(st: &State, q: &HashMap<String, String>) -> Result<Response<Full<Bytes>>> {
    let text = q.get("question_text_sha256").cloned();
    let auditee = q.get("auditee").cloned();
    if text.is_none() && auditee.is_none() {
        bail!("give question_text_sha256 or auditee");
    }
    let entries: Vec<RunLogEntry> = st
        .log
        .lock()
        .unwrap()
        .iter()
        .filter(|e| text.as_ref().map_or(true, |t| &e.question_text_sha256 == t))
        .filter(|e| auditee.as_ref().map_or(true, |a| &e.auditee_public_key == a))
        .cloned()
        .collect();
    let body = RunLogBody {
        boot_id: st.info.boot_id.clone(),
        booted_at_ms: st.info.booted_at_ms,
        generated_at_ms: now_ms(),
        query: RunLogQuery { question_text_sha256: text, auditee_public_key: auditee },
        entries,
    };
    Ok(json_response(
        StatusCode::OK,
        &RunLogResponse {
            enclave_info_json: st.info_json.clone(),
            boot_document_b64: st.boot_doc_b64.clone(),
            signed: sign::sign(&st.signing, DOMAIN_RUN_LOG, &body)?,
        },
    ))
}
