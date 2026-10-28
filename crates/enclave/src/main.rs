//! attest enclave: hosts two-party audit sessions. A model with read-only
//! tools reads the auditee's code and answers the auditor's question; the
//! auditee decides whether the auditor sees the answer.
//!
//! TLS terminates inside the enclave with a key generated at boot and bound
//! to the attestation document, so the web page and API come from the
//! measured image. See web/agents.md for the protocol.

mod acme;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod aws;
mod blobs;
mod bundle;
mod harnesses;
mod jail;
mod llm;
mod modelproxy;
mod net;
mod notify;
mod nsm;
mod run;
mod sandbox;
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
    /// Dev only: address of the host's blob store.
    #[arg(long, default_value = "127.0.0.1:5005")]
    dev_blobs: String,
    /// Dev only: host config JSON (what the parent serves over vsock in production).
    #[arg(long)]
    dev_config: Option<String>,
    #[arg(long, default_value_t = 4)]
    concurrency: usize,
    /// CPython WASI build: python.wasm and lib/python3.x.
    #[arg(long, default_value = "/opt/python-wasi")]
    python_dir: String,
}

/// Supplied by the untrusted parent at boot. Nothing in it is trusted for
/// security: the domain only affects which certificate is requested, and
/// the email key only lets the enclave send mail.
#[derive(serde::Deserialize, Default, Debug)]
struct HostConfig {
    domain: Option<String>,
    acme_directory: Option<String>,
    /// Sender for notification emails (must be verified in SES). No email without it.
    email_from: Option<String>,
    /// SES region (defaults to the instance's region, as the host reports it).
    ses_region: Option<String>,
    /// The server's public IP, for an IP-address certificate when there's no domain.
    public_ip: Option<String>,
    max_code_mib: Option<usize>,
    /// Shown on the landing page as "run by ...". Unverified.
    operator: Option<String>,
}

const LOG_VSOCK_PORT: u32 = 5004;
static LOG_TX: std::sync::OnceLock<tokio::sync::mpsc::Sender<String>> = std::sync::OnceLock::new();

/// Operational log. Production enclaves have no console (and `eprintln!`
/// panics when stderr is gone), so lines go to the parent over vsock, best
/// effort. Never log code, keys, tokens or email addresses.
pub fn log(msg: &str) {
    use std::io::Write;
    let line = format!("[attest-enclave] {msg}");
    let _ = writeln!(std::io::stderr(), "{line}");
    if let Some(tx) = LOG_TX.get() {
        let _ = tx.try_send(line);
    }
}

fn start_log_forwarding(dev: bool) {
    if dev {
        return;
    }
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(1000);
    let _ = LOG_TX.set(tx);
    tokio::spawn(async move {
        #[cfg(target_os = "linux")]
        {
            use tokio::io::AsyncWriteExt;
            let mut conn: Option<tokio_vsock::VsockStream> = None;
            while let Some(line) = rx.recv().await {
                if conn.is_none() {
                    conn = crate::net::vsock_connect(LOG_VSOCK_PORT).await.ok();
                }
                if let Some(c) = conn.as_mut() {
                    if c.write_all(format!("{line}\n").as_bytes()).await.is_err() {
                        conn = None;
                    }
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        while rx.recv().await.is_some() {}
        let _ = LOG_VSOCK_PORT;
    });
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
        // The parent's config service may start after us, or drop a
        // connection; retry the whole exchange for a minute.
        let mut last = String::new();
        for _ in 0..60 {
            let attempt = async {
                let mut s = tokio::time::timeout(
                    Duration::from_secs(5),
                    crate::net::vsock_connect(CONFIG_VSOCK_PORT),
                )
                .await
                .map_err(|_| anyhow!("timeout"))??;
                let mut buf = Vec::new();
                tokio::time::timeout(
                    Duration::from_secs(5),
                    (&mut s).take(1 << 20).read_to_end(&mut buf),
                )
                .await
                .map_err(|_| anyhow!("timeout"))??;
                anyhow::Ok(serde_json::from_slice::<HostConfig>(&buf).context("host config JSON")?)
            };
            match attempt.await {
                Ok(c) => return Ok(c),
                Err(e) => last = format!("{e:#}"),
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        bail!("cannot read the parent config on vsock {CONFIG_VSOCK_PORT}: {last}")
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = CONFIG_VSOCK_PORT;
        bail!("vsock requires linux; run with --dev")
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::args().nth(1).as_deref() == Some("--jail-exec") {
        jail::exec_main(&std::env::args().nth(2).unwrap_or_default());
    }
    if std::env::args().nth(1).as_deref() == Some("--jail-probe") {
        println!("{}", jail::probe());
        return Ok(());
    }
    let args = Args::parse();
    start_log_forwarding(args.dev);
    let attester = nsm::Attester::new(args.dev)?;
    let cfg = read_host_config(&args).await?;
    log(&format!(
        "config: domain={:?} public_ip={:?} email_from={:?}",
        cfg.domain, cfg.public_ip, cfg.email_from
    ));
    let domain = cfg.domain.clone().filter(|_| !args.dev);
    // The name to get a certificate for: the domain, or else the public IP
    // (Let's Encrypt issues short-lived certificates for IP addresses).
    let cert_name = domain
        .clone()
        .or_else(|| {
            cfg.public_ip
                .clone()
                .filter(|ip| ip.parse::<std::net::IpAddr>().is_ok())
        })
        .filter(|_| !args.dev);
    let tls = if args.dev {
        None
    } else {
        Some(Arc::new(tls::ServerIdentity::generate(
            cert_name.as_slice(),
        )?))
    };

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
            agents: harnesses::available(),
        },
    };
    let info_json = serde_json::to_string(&info)?;
    let boot_doc = attester.attest(
        &sha256(info_json.as_bytes()),
        &signing.verifying_key().to_bytes(),
        None,
    )?;
    let net = net::Net::new(args.dev, args.dev_tunnel.clone())?;
    // Egress allowlist: everything this enclave may ever connect to.
    for p in [Provider::Openai, Provider::Anthropic, Provider::Openrouter] {
        net.allow(llm::endpoint(p).0);
    }
    let acme_dir = cfg
        .acme_directory
        .clone()
        .unwrap_or_else(|| LETS_ENCRYPT.into());
    if let Some(h) = url::Url::parse(&acme_dir)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
    {
        net.allow(&h);
    }
    if let Some(n) = &cert_name {
        net.allow(n); // the DNS self-check before requesting a certificate
    }
    if cfg.email_from.is_some() {
        net.allow(&format!(
            "email.{}.amazonaws.com",
            cfg.ses_region.clone().unwrap_or_else(|| "us-west-2".into())
        ));
    }
    log(&format!(
        "egress allowlist: {}",
        net.allowed_hosts().join(", ")
    ));
    let ctx = Arc::new(Ctx {
        dev: args.dev,
        net: net.clone(),
        boot_doc_b64: boot_doc.map(|d| base64::engine::general_purpose::STANDARD.encode(d)),
        info,
        info_json,
        signing,
        email: cfg.email_from.clone().map(|from| notify::EmailConfig {
            from,
            region: cfg.ses_region.clone().unwrap_or_else(|| "us-west-2".into()),
        }),
        email_limiter: notify::Limiter::default(),
        public_name: domain.clone().or(cfg.public_ip.clone()),
        max_code_bytes: cfg.max_code_mib.unwrap_or(1024) << 20,
        blobs: blobs::BlobClient::new(args.dev, args.dev_blobs.clone()),
        // Fixed in the image: a host-chosen size would let the host shape
        // which reads miss and reach it.
        cache: Arc::new(blobs::Cache::new(256 << 20)),
        upload_slots: tokio::sync::Semaphore::new(2),
        sandbox: Arc::new(std::sync::OnceLock::new()),
        slots: tokio::sync::Semaphore::new(args.concurrency),
        disclosure_slots: tokio::sync::Semaphore::new(1),
        store: sessions::Store::default(),
    });
    let app = Arc::new(App {
        ctx: ctx.clone(),
        attester,
    });
    tokio::spawn(measure_blob_store(ctx.blobs.clone()));
    if !args.dev {
        jail::spawn_probe();
        let _ = std::fs::create_dir_all("/jails");
    }
    {
        let (slot, dir) = (ctx.sandbox.clone(), args.python_dir.clone());
        tokio::task::spawn_blocking(move || {
            let t = std::time::Instant::now();
            match sandbox::Sandbox::load(std::path::Path::new(&dir)) {
                Ok(sb) => {
                    let _ = slot.set(Arc::new(sb));
                    log(&format!(
                        "python sandbox ready ({:.1} s to compile)",
                        t.elapsed().as_secs_f64()
                    ));
                }
                Err(e) => log(&format!("python sandbox unavailable: {e:#}")),
            }
        });
    }
    log(&format!(
        "boot {} mode={} commit={}",
        ctx.info.boot_id, ctx.info.mode, ctx.info.source_commit
    ));

    if let (Some(t), Some(d)) = (&tls, &cert_name) {
        tokio::spawn(acme::run(net, t.clone(), d.clone(), acme_dir));
    }
    serve(args, app, tls).await
}

/// Time a 16 MiB round trip to the parent's blob store, for the log.
async fn measure_blob_store(store: blobs::BlobClient) {
    let mut data = vec![0u8; 16 << 20];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut data);
    let mut id = [0u8; 24];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
    let t0 = std::time::Instant::now();
    if let Err(e) = store.put(&id, &data).await {
        log(&format!("blob store check failed: {e:#}"));
        return;
    }
    let put = t0.elapsed();
    let t1 = std::time::Instant::now();
    let ok = matches!(store.get(&id).await, Ok(Some(d)) if d == data);
    let get = t1.elapsed();
    let mb = 16.0;
    // Small-request latency.
    let mut tiny = [0u8; 24];
    tiny[0] = 0xff;
    let t2 = std::time::Instant::now();
    for _ in 0..20 {
        let _ = store.get(&tiny).await;
    }
    let rtt = t2.elapsed() / 20;
    // Eight 2 MiB transfers at once, as grep does.
    let t3 = std::time::Instant::now();
    let parallel = futures_util::future::join_all((0..8u8).map(|i| {
        let store = store.clone();
        let mut pid = id;
        pid[23] ^= i.wrapping_add(1);
        let chunk = data[..2 << 20].to_vec();
        async move {
            store.put(&pid, &chunk).await.is_ok()
                && matches!(store.get(&pid).await, Ok(Some(d)) if d.len() == chunk.len())
        }
    }))
    .await;
    let par = t3.elapsed();
    let par_ok = parallel.iter().all(|x| *x);
    let _ = store.delete_session(&id[..8].try_into().unwrap()).await;
    log(&format!(
        "blob store: 8 parallel 2 MiB put+get {:.0} ms ({:.0} MB/s each way), ok={par_ok}",
        par.as_secs_f64() * 1e3,
        16.0 / par.as_secs_f64() * 2.0 / 2.0
    ));
    log(&format!(
        "blob store: 16 MiB put {:.0} ms ({:.0} MB/s), get {:.0} ms ({:.0} MB/s), small request {:.2} ms, verified={ok}",
        put.as_secs_f64() * 1e3, mb / put.as_secs_f64(), get.as_secs_f64() * 1e3, mb / get.as_secs_f64(), rtt.as_secs_f64() * 1e3
    ));
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
        let l = tokio_vsock::VsockListener::bind(tokio_vsock::VsockAddr::new(
            tokio_vsock::VMADDR_CID_ANY,
            LISTEN_VSOCK_PORT,
        ))
        .context("binding vsock")?;
        log(&format!(
            "listening on vsock port {LISTEN_VSOCK_PORT} (TLS)"
        ));
        loop {
            let (s, _) = l.accept().await?;
            // The vsock crate accepts without SOCK_CLOEXEC; see net::vsock_connect.
            crate::net::cloexec(std::os::fd::AsRawFd::as_raw_fd(&s));
            let (app, acceptor) = (app.clone(), acceptor.clone());
            tokio::spawn(async move {
                let Ok(Ok(stream)) =
                    tokio::time::timeout(Duration::from_secs(20), acceptor.accept(s)).await
                else {
                    return;
                };
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

async fn serve_http<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>(
    app: Arc<App>,
    s: S,
) {
    let svc = hyper::service::service_fn(move |req| {
        let app = app.clone();
        async move { Ok::<_, std::convert::Infallible>(handle(app, req).await) }
    });
    let _ = hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(s), svc)
        .await;
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
    respond(
        status,
        "application/json",
        // Padded: the parent sees response sizes, and some responses (the
        // auditee's trace) carry model-influenced content.
        llm::pad_json(serde_json::to_vec(v).unwrap_or_default()),
    )
}

struct ApiError(StatusCode, String);

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError(StatusCode::BAD_REQUEST, format!("{e:#}"))
    }
}

fn query(req: &Request<hyper::body::Incoming>) -> HashMap<String, String> {
    req.uri()
        .query()
        .map(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .into_owned()
                .collect()
        })
        .unwrap_or_default()
}

async fn body_json(req: Request<hyper::body::Incoming>) -> Result<Value, ApiError> {
    let b = http_body_util::Limited::new(req.into_body(), 1 << 20)
        .collect()
        .await
        .map_err(|_| {
            ApiError(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body too large".into(),
            )
        })?
        .to_bytes();
    if b.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&b)
        .map_err(|e| ApiError(StatusCode::BAD_REQUEST, format!("body is not JSON: {e}")))
}

async fn handle(app: Arc<App>, req: Request<hyper::body::Incoming>) -> Resp {
    let path = req.uri().path().to_string();
    let method = req.method().as_str().to_string();
    let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    let r: Result<Resp, ApiError> = match (method.as_str(), parts.as_slice()) {
        ("GET", [""]) | ("GET", ["s", _]) => Ok(respond(
            StatusCode::OK,
            "text/html; charset=utf-8",
            INDEX_HTML,
        )),
        ("GET", ["agents.md"]) | ("GET", ["llms.txt"]) => Ok(respond(
            StatusCode::OK,
            "text/markdown; charset=utf-8",
            AGENTS_MD,
        )),
        ("GET", ["healthz"]) => Ok(json_resp(StatusCode::OK, &json!({"ok": true}))),
        ("GET", ["api", "attestation"]) => attestation(&app, &query(&req)),
        ("GET", ["api", "info"]) => Ok(json_resp(
            StatusCode::OK,
            &serde_json::to_value(&app.ctx.info).unwrap_or_default(),
        )),
        ("POST", ["api", "sessions"]) => create_session(&app, &req),
        (_, ["api", "sessions", id, rest @ ..]) => session_route(&app, id, rest, req).await,
        _ => Err(ApiError(
            StatusCode::NOT_FOUND,
            format!("not found: {method} {path} (see /agents.md)"),
        )),
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
                .attest(
                    &sha256(ctx.info_json.as_bytes()),
                    &ctx.signing.verifying_key().to_bytes(),
                    Some(&nonce),
                )?
                .map(|d| base64::engine::general_purpose::STANDARD.encode(d))
        }
        None => app.ctx.boot_doc_b64.clone(),
    };
    let r = AttestationResponse {
        enclave_info_json: app.ctx.info_json.clone(),
        document_b64: doc,
    };
    Ok(json_resp(
        StatusCode::OK,
        &serde_json::to_value(r).unwrap_or_default(),
    ))
}

fn base_url(app: &App, req: &Request<hyper::body::Incoming>) -> String {
    match &app.ctx.public_name {
        Some(d) => format!("https://{d}"),
        None => {
            let host = req
                .headers()
                .get("host")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("127.0.0.1:8080");
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

/// Stream an uploaded tar into a sealed bundle: body frames go through a
/// bounded channel to a blocking parser, so at most a few frames and one
/// file are in memory at a time.
async fn ingest_upload(
    ctx: &Arc<Ctx>,
    session_id: &str,
    mut body: hyper::body::Incoming,
) -> Result<bundle::Bundle, ApiError> {
    let max = ctx.max_code_bytes as u64;
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(16);
    let (store, cache, sid) = (ctx.blobs.clone(), ctx.cache.clone(), session_id.to_string());
    let rt = tokio::runtime::Handle::current();
    let job = tokio::task::spawn_blocking(move || {
        bundle::Bundle::ingest(
            ChannelReader {
                rx,
                buf: Bytes::new(),
            },
            &sid,
            store,
            cache,
            rt,
            max,
        )
    });
    let mut received = 0u64;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| anyhow!("upload interrupted: {e}"))?;
        if let Ok(data) = frame.into_data() {
            received += data.len() as u64;
            // The tar has headers and padding on top of file contents.
            if received > max + max / 8 + (16 << 20) {
                return Err(ApiError(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    format!("the archive is larger than {} MiB", max >> 20),
                ));
            }
            if tx.send(data).await.is_err() {
                break; // the parser stopped early (error); its result says why
            }
        }
    }
    drop(tx);
    let b = job.await.map_err(|_| anyhow!("upload parser crashed"))??;
    Ok(b)
}

struct ChannelReader {
    rx: tokio::sync::mpsc::Receiver<Bytes>,
    buf: Bytes,
}

impl std::io::Read for ChannelReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while self.buf.is_empty() {
            match self.rx.blocking_recv() {
                Some(b) => self.buf = b,
                None => return Ok(0),
            }
        }
        let n = out.len().min(self.buf.len());
        out[..n].copy_from_slice(&self.buf[..n]);
        self.buf = self.buf.slice(n..);
        Ok(n)
    }
}

fn bearer(req: &Request<hyper::body::Incoming>) -> Option<String> {
    req.headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(|t| t.trim().to_string())
}

async fn session_route(
    app: &Arc<App>,
    id: &str,
    rest: &[&str],
    req: Request<hyper::body::Incoming>,
) -> Result<Resp, ApiError> {
    let ctx = &app.ctx;
    let token = bearer(&req).ok_or_else(|| {
        ApiError(
            StatusCode::UNAUTHORIZED,
            "send the token from your link as 'Authorization: Bearer <token>'".into(),
        )
    })?;
    let (s, role) = ctx
        .store
        .auth(id, &token)
        .map_err(|e| ApiError(StatusCode::NOT_FOUND, e.to_string()))?;
    s.touch(ctx, role);
    let method = req.method().as_str().to_string();
    let q = query(&req);
    let ok = |v: Value| Ok(json_resp(StatusCode::OK, &v));
    match (method.as_str(), rest) {
        ("GET", []) => {
            // Long-poll: ?version=N&wait=25 returns once the session changes past N.
            if let Some(v) = q.get("version").and_then(|v| v.parse::<u64>().ok()) {
                let wait = q
                    .get("wait")
                    .and_then(|w| w.parse::<u64>().ok())
                    .unwrap_or(0)
                    .min(30);
                if wait > 0 {
                    sessions::wait_for_change(&s, role, v, Duration::from_secs(wait)).await;
                }
            }
            let since = q.get("since").and_then(|v| v.parse().ok()).unwrap_or(0);
            ok(s.view(ctx, role, since))
        }
        ("POST", ["question"]) => ok(s.propose_question(ctx, role, &body_json(req).await?)?),
        ("POST", ["question", "decision"]) => {
            ok(s.decide_question(ctx, role, &body_json(req).await?)?)
        }
        ("PUT", ["code"]) => {
            if role != attest_core::Role::Auditee {
                return Err(anyhow!("only the auditee uploads code").into());
            }
            let _slot = ctx
                .upload_slots
                .acquire()
                .await
                .map_err(|_| anyhow!("shutting down"))?;
            let bundle = ingest_upload(ctx, &s.id, req.into_body()).await?;
            ok(s.set_code(ctx, role, bundle)?)
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
        ("POST", ["runs", rid, "release"]) => {
            ok(s.decide_release(ctx, role, rid, &body_json(req).await?)?)
        }
        ("POST", ["runs", rid, "followup"]) => {
            ok(s.followup(ctx, role, rid, &body_json(req).await?)?)
        }
        ("GET", ["runs", rid, "certificate"]) => {
            ok(serde_json::to_value(s.certificate(ctx, role, rid)?).map_err(anyhow::Error::from)?)
        }
        ("POST", ["disclosures"]) => ok(s
            .draft_disclosure(ctx, role, &body_json(req).await?)
            .await?),
        ("POST", ["disclosures", n, "decision"]) => {
            let n: u32 = n.parse().map_err(|_| anyhow!("bad disclosure number"))?;
            ok(s.decide_disclosure(ctx, role, n, &body_json(req).await?)?)
        }
        ("GET", ["disclosures", n]) => {
            let n: u32 = n.parse().map_err(|_| anyhow!("bad disclosure number"))?;
            ok(serde_json::to_value(s.disclosure(role, n)?).map_err(anyhow::Error::from)?)
        }
        ("POST", ["notify"]) => ok(s.set_notify(ctx, role, &body_json(req).await?)?),
        _ => Err(ApiError(
            StatusCode::NOT_FOUND,
            format!(
                "not found: {method} /api/sessions/{id}/{} (see /agents.md)",
                rest.join("/")
            ),
        )),
    }
}
