//! attest enclave: hosts two-party audit sessions. A model with read-only
//! tools reads the auditee's code and answers the auditor's question; the
//! auditee decides whether the auditor sees the answer.
//!
//! TLS terminates inside the enclave with a key generated at boot and bound
//! to the attestation document, so the web page and API come from the
//! measured image. See web/agents.md for the protocol.

mod acme;
mod bundle;
mod llm;
mod net;
mod notify;
mod nsm;
mod run;
mod sessions;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod tls;

#[allow(unused_imports)]
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
use serde_json::{json, Value};
use sessions::Ctx;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

const LISTEN_VSOCK_PORT: u32 = 5000;
const CONFIG_VSOCK_PORT: u32 = 5002;
const INDEX_HTML: &str = include_str!("../web/index.html");
const AGENTS_MD: &str = include_str!("../web/agents.md");
const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";

#[derive(Parser, Debug)]
#[command(name = "attest-enclave")]
struct Args {
    /// Local development: plain HTTP on loopback, no attestation, mock provider allowed.
    #[arg(long)]
    dev: bool,
    #[arg(long, default_value = "127.0.0.1:8080")]
    dev_listen: String,
    #[arg(long, default_value = "127.0.0.1:5001")]
    dev_tunnel: String,
    /// Dev only: host config JSON (what the parent serves over vsock in production).
    #[arg(long)]
    dev_config: Option<String>,
    #[arg(long, default_value_t = 4)]
    concurrency: usize,
}

/// Supplied by the untrusted parent at boot. Nothing in it is trusted for
/// security: the domain only affects which certificate is requested, and
/// the email key only lets the enclave send mail.
#[derive(serde::Deserialize, Default, Debug)]
struct HostConfig {
    domain: Option<String>,
    acme_directory: Option<String>,
    email: Option<notify::EmailConfig>,
    max_code_mib: Option<usize>,
    max_total_code_mib: Option<usize>,
    /// Shown on the landing page as "run by ...". Unverified.
    operator: Option<String>,
}

pub fn log(msg: &str) {
    eprintln!("[attest-enclave] {msg}");
}

async fn read_host_config(args: &Args) -> Result<HostConfig> {
    if args.dev {
        return match &args.dev_config {
            Some(p) => Ok(serde_json::from_str(&std::fs::read_to_string(p)?)?),
            None => Ok(HostConfig::default()),
        };
    }
    #[cfg(target_os = "linux")]
    {
        use tokio::io::AsyncReadExt;
        let addr = tokio_vsock::VsockAddr::new(tokio_vsock::VMADDR_CID_HOST, CONFIG_VSOCK_PORT);
        // The parent's config service may start after us; keep trying for a minute.
        let mut attempt = 0;
        let mut s = loop {
            match tokio::time::timeout(Duration::from_secs(5), tokio_vsock::VsockStream::connect(addr)).await {
                Ok(Ok(s)) => break s,
                _ if attempt < 60 => {
                    attempt += 1;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                _ => bail!("cannot reach the parent config service on vsock {CONFIG_VSOCK_PORT}"),
            }
        };
        let mut buf = Vec::new();
        (&mut s).take(1 << 20).read_to_end(&mut buf).await?;
        Ok(serde_json::from_slice(&buf).context("host config JSON")?)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = CONFIG_VSOCK_PORT;
        bail!("vsock requires linux; run with --dev")
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let attester = nsm::Attester::new(args.dev)?;
    let cfg = read_host_config(&args).await?;
    log(&format!("config: domain={:?} email={}", cfg.domain, cfg.email.is_some()));
    let domain = cfg.domain.clone().filter(|_| !args.dev);
    let tls = if args.dev { None } else { Some(Arc::new(tls::ServerIdentity::generate(domain.as_slice())?)) };

    // Inside Nitro the kernel RNG is fed by the NSM hardware RNG.
    let signing = SigningKey::generate(&mut rand::rngs::OsRng);
    let mut endpoints = BTreeMap::new();
    for p in [Provider::Openai, Provider::Anthropic, Provider::Openrouter] {
        let (h, path) = llm::endpoint(p);
        endpoints.insert(p.as_str().to_string(), format!("https://{h}{path}"));
    }
    let mut boot = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut boot);
    let info = EnclaveInfo {
        service: "attest".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        source_repo: SOURCE_REPO.into(),
        source_commit: option_env!("ATTEST_GIT_SHA").unwrap_or("unknown").into(),
        mode: if args.dev { "dev" } else { "nitro" }.into(),
        boot_id: hex::encode(boot),
        booted_at_ms: now_ms(),
        signing_public_key: hex::encode(signing.verifying_key().to_bytes()),
        tls_spki_sha256: tls.as_ref().map(|t| t.spki_sha256.clone()),
        domain: domain.clone(),
        operator: cfg.operator.clone().map(|o| o.chars().take(120).collect()),
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
    let net = net::Net::new(args.dev, args.dev_tunnel.clone())?;
    let ctx = Arc::new(Ctx {
        dev: args.dev,
        net: net.clone(),
        boot_doc_b64: boot_doc.map(|d| base64::engine::general_purpose::STANDARD.encode(d)),
        info,
        info_json,
        signing,
        email: cfg.email,
        max_code_bytes: cfg.max_code_mib.unwrap_or(1024) << 20,
        max_total_code_bytes: cfg.max_total_code_mib.unwrap_or(4096) << 20,
        slots: tokio::sync::Semaphore::new(args.concurrency),
        store: sessions::Store::default(),
    });
    let app = Arc::new(App { ctx: ctx.clone(), attester });
    log(&format!("boot {} mode={} commit={}", ctx.info.boot_id, ctx.info.mode, ctx.info.source_commit));

    if let (Some(t), Some(d)) = (&tls, &domain) {
        tokio::spawn(acme::run(net, t.clone(), d.clone(), cfg.acme_directory.unwrap_or_else(|| LETS_ENCRYPT.into())));
    }
    serve(args, app, tls).await
}

struct App {
    ctx: Arc<Ctx>,
    attester: nsm::Attester,
}

async fn serve(args: Args, app: Arc<App>, tls: Option<Arc<tls::ServerIdentity>>) -> Result<()> {
    if args.dev {
        let l = tokio::net::TcpListener::bind(&args.dev_listen).await?;
        log(&format!("dev: http://{}/", args.dev_listen));
        loop {
            let (s, _) = l.accept().await?;
            let app = app.clone();
            tokio::spawn(async move { serve_http(app, s).await });
        }
    }
    #[cfg(target_os = "linux")]
    {
        let tls = tls.ok_or_else(|| anyhow!("no TLS identity"))?;
        let acceptor = tokio_rustls::TlsAcceptor::from(tls.server_config());
        let l = tokio_vsock::VsockListener::bind(tokio_vsock::VsockAddr::new(tokio_vsock::VMADDR_CID_ANY, LISTEN_VSOCK_PORT))
            .context("binding vsock")?;
        log(&format!("listening on vsock port {LISTEN_VSOCK_PORT} (TLS)"));
        loop {
            let (s, _) = l.accept().await?;
            let (app, acceptor) = (app.clone(), acceptor.clone());
            tokio::spawn(async move {
                let Ok(Ok(stream)) = tokio::time::timeout(Duration::from_secs(20), acceptor.accept(s)).await else { return };
                // ACME validation connections only need the handshake.
                if stream.get_ref().1.alpn_protocol() == Some(tls::ACME_ALPN) {
                    return;
                }
                serve_http(app, stream).await
            });
        }
    }
    #[allow(unreachable_code)]
    {
        let _ = (tls, LISTEN_VSOCK_PORT);
        bail!("vsock requires linux; run with --dev")
    }
}

async fn serve_http<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>(app: Arc<App>, s: S) {
    let svc = hyper::service::service_fn(move |req| {
        let app = app.clone();
        async move { Ok::<_, std::convert::Infallible>(handle(app, req).await) }
    });
    let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(s), svc).await;
}

// ------------------------------------------------------------------ HTTP

type Resp = Response<Full<Bytes>>;

fn respond(status: StatusCode, ctype: &str, body: impl Into<Bytes>) -> Resp {
    Response::builder()
        .status(status)
        .header("content-type", ctype)
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff")
        .header("referrer-policy", "no-referrer")
        .header("x-frame-options", "DENY")
        .header(
            "content-security-policy",
            "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        )
        .body(Full::new(body.into()))
        .unwrap()
}

fn json_resp(status: StatusCode, v: &Value) -> Resp {
    respond(status, "application/json", serde_json::to_vec(v).unwrap_or_default())
}

struct ApiError(StatusCode, String);

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError(StatusCode::BAD_REQUEST, format!("{e:#}"))
    }
}

fn query(req: &Request<hyper::body::Incoming>) -> HashMap<String, String> {
    req.uri().query().map(|q| url::form_urlencoded::parse(q.as_bytes()).into_owned().collect()).unwrap_or_default()
}

async fn body_json(req: Request<hyper::body::Incoming>) -> Result<Value, ApiError> {
    let b = http_body_util::Limited::new(req.into_body(), 1 << 20)
        .collect()
        .await
        .map_err(|_| ApiError(StatusCode::PAYLOAD_TOO_LARGE, "request body too large".into()))?
        .to_bytes();
    if b.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&b).map_err(|e| ApiError(StatusCode::BAD_REQUEST, format!("body is not JSON: {e}")))
}

async fn handle(app: Arc<App>, req: Request<hyper::body::Incoming>) -> Resp {
    let path = req.uri().path().to_string();
    let method = req.method().as_str().to_string();
    let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    let r: Result<Resp, ApiError> = match (method.as_str(), parts.as_slice()) {
        ("GET", [""]) | ("GET", ["s", _]) => Ok(respond(StatusCode::OK, "text/html; charset=utf-8", INDEX_HTML)),
        ("GET", ["agents.md"]) | ("GET", ["llms.txt"]) => Ok(respond(StatusCode::OK, "text/markdown; charset=utf-8", AGENTS_MD)),
        ("GET", ["healthz"]) => Ok(json_resp(StatusCode::OK, &json!({"ok": true}))),
        ("GET", ["api", "attestation"]) => attestation(&app, &query(&req)),
        ("GET", ["api", "info"]) => Ok(json_resp(StatusCode::OK, &serde_json::to_value(&app.ctx.info).unwrap_or_default())),
        ("POST", ["api", "sessions"]) => create_session(&app, &req),
        (_, ["api", "sessions", id, rest @ ..]) => session_route(&app, id, rest, req).await,
        _ => Err(ApiError(StatusCode::NOT_FOUND, format!("not found: {method} {path} (see /agents.md)"))),
    };
    r.unwrap_or_else(|ApiError(s, m)| json_resp(s, &json!({"error": m})))
}

fn attestation(app: &App, q: &HashMap<String, String>) -> Result<Resp, ApiError> {
    let doc = match q.get("nonce") {
        Some(n) => {
            let nonce = hex::decode(n).map_err(|_| anyhow!("nonce must be hex"))?;
            if nonce.is_empty() || nonce.len() > 64 {
                return Err(anyhow!("nonce must be 1-64 bytes").into());
            }
            let ctx = &app.ctx;
            app.attester
                .attest(&sha256(ctx.info_json.as_bytes()), &ctx.signing.verifying_key().to_bytes(), Some(&nonce))?
                .map(|d| base64::engine::general_purpose::STANDARD.encode(d))
        }
        None => app.ctx.boot_doc_b64.clone(),
    };
    let r = AttestationResponse { enclave_info_json: app.ctx.info_json.clone(), document_b64: doc };
    Ok(json_resp(StatusCode::OK, &serde_json::to_value(r).unwrap_or_default()))
}

fn base_url(app: &App, req: &Request<hyper::body::Incoming>) -> String {
    match &app.ctx.info.domain {
        Some(d) => format!("https://{d}"),
        None => {
            let host = req.headers().get("host").and_then(|h| h.to_str().ok()).unwrap_or("127.0.0.1:8080");
            format!("{}://{host}", if app.ctx.dev { "http" } else { "https" })
        }
    }
}

fn create_session(app: &App, req: &Request<hyper::body::Incoming>) -> Result<Resp, ApiError> {
    let (s, auditee, auditor) = app.ctx.store.create()?;
    let base = base_url(app, req);
    log(&format!("session {} created", &s.id[..8]));
    Ok(json_resp(
        StatusCode::OK,
        &json!({
            "session_id": s.id,
            "auditee_token": auditee,
            "auditor_token": auditor,
            "auditee_link": format!("{base}/s/{}#{auditee}", s.id),
            "auditor_link": format!("{base}/s/{}#{auditor}", s.id),
            "note": "Keep the auditee link. Send the auditor link to the auditor over a channel you trust. Anyone with a link acts as that party.",
        }),
    ))
}

fn bearer(req: &Request<hyper::body::Incoming>) -> Option<String> {
    req.headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(|t| t.trim().to_string())
}

async fn session_route(app: &Arc<App>, id: &str, rest: &[&str], req: Request<hyper::body::Incoming>) -> Result<Resp, ApiError> {
    let ctx = &app.ctx;
    let token = bearer(&req).ok_or_else(|| ApiError(StatusCode::UNAUTHORIZED, "send the token from your link as 'Authorization: Bearer <token>'".into()))?;
    let (s, role) = ctx.store.auth(id, &token).map_err(|e| ApiError(StatusCode::NOT_FOUND, e.to_string()))?;
    s.touch(ctx, role);
    let method = req.method().as_str().to_string();
    let q = query(&req);
    let ok = |v: Value| Ok(json_resp(StatusCode::OK, &v));
    match (method.as_str(), rest) {
        ("GET", []) => {
            // Long-poll: ?version=N&wait=25 returns once the session changes past N.
            if let Some(v) = q.get("version").and_then(|v| v.parse::<u64>().ok()) {
                let wait = q.get("wait").and_then(|w| w.parse::<u64>().ok()).unwrap_or(0).min(30);
                if wait > 0 {
                    sessions::wait_for_change(&s, v, Duration::from_secs(wait)).await;
                }
            }
            let since = q.get("since").and_then(|v| v.parse().ok()).unwrap_or(0);
            ok(s.view(ctx, role, since))
        }
        ("POST", ["question"]) => ok(s.propose_question(ctx, role, &body_json(req).await?)?),
        ("POST", ["question", "decision"]) => ok(s.decide_question(ctx, role, &body_json(req).await?)?),
        ("PUT", ["code"]) => {
            if role != Role::Auditee {
                return Err(anyhow!("only the auditee uploads code").into());
            }
            let used = ctx.store.total_code_bytes() as usize;
            let room = ctx.max_total_code_bytes.saturating_sub(used);
            let limit = ctx.max_code_bytes.min(room);
            if limit < 1024 {
                return Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "this server is out of room for code right now".into()));
            }
            let tar = http_body_util::Limited::new(req.into_body(), limit)
                .collect()
                .await
                .map_err(|_| ApiError(StatusCode::PAYLOAD_TOO_LARGE, format!("code archive is larger than {} MiB", limit >> 20)))?
                .to_bytes();
            ok(s.upload_code(ctx, role, &tar)?)
        }
        ("POST", ["affidavit"]) => ok(s.confirm_affidavit(ctx, role, &body_json(req).await?)?),
        ("POST", ["models"]) => ok(s.propose_model(ctx, role, &body_json(req).await?)?),
        ("POST", ["models", mid, "decision"]) => {
            let mid: u32 = mid.parse().map_err(|_| anyhow!("bad model id"))?;
            ok(s.decide_model(ctx, role, mid, &body_json(req).await?)?)
        }
        ("GET", ["runs", rid, "trace"]) => {
            let after = q.get("after").and_then(|v| v.parse().ok()).unwrap_or(0);
            ok(s.trace(role, rid, after)?)
        }
        ("POST", ["runs", rid, "release"]) => ok(s.decide_release(ctx, role, rid, &body_json(req).await?)?),
        ("POST", ["runs", rid, "followup"]) => ok(s.followup(ctx, role, rid, &body_json(req).await?)?),
        ("GET", ["runs", rid, "certificate"]) => ok(serde_json::to_value(s.certificate(role, rid)?).map_err(anyhow::Error::from)?),
        ("POST", ["notify"]) => ok(s.set_notify(role, &body_json(req).await?, ctx.email.is_some())?),
        _ => Err(ApiError(StatusCode::NOT_FOUND, format!("not found: {method} /api/sessions/{id}/{} (see /agents.md)", rest.join("/")))),
    }
}

