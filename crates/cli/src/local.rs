//! `attest open`: a local client for the web app.
//!
//! A browser can't tell which key its TLS session ends at, so a page served
//! straight from the server can't prove it came from the enclave: whoever
//! controls the domain or IP could get their own certificate and serve
//! different JavaScript. This client checks the attestation itself, on each
//! TLS session it opens, and only then relays traffic: the browser talks to
//! 127.0.0.1, and everything past that runs over sessions checked to end
//! inside an enclave running the expected build.

use crate::{Conn, PolicyArgs};
use anyhow::{anyhow, bail, Context, Result};
use attest_core::nitro::ExpectedPcrs;
use attest_core::verify::EnclavePolicy;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

pub const MEASUREMENTS_REPO: &str = "sophiawisdom/attest";
/// Request bodies the client relays (code uploads from the folder picker).
const MAX_BODY: usize = 1 << 30;

struct State {
    base: url::Url,
    policy: EnclavePolicy,
    /// Attested connections not currently in use.
    idle: Mutex<Vec<Conn>>,
    /// Set after any failed check: from then on nothing is relayed.
    failed: AtomicBool,
    pcr0: Option<String>,
    index: String,
    local_host: String,
}

/// The policy to check a server with. Without --pcrs, the measurements
/// published in `measurements_repo` for the commit the server names. (The
/// server's claim only picks which file to fetch; the attestation is what
/// gets checked against it.) Also says where the measurements came from.
pub async fn expected_policy(conn: &mut Conn, measurements_repo: &str, args: &PolicyArgs) -> Result<(EnclavePolicy, String)> {
    let mut policy = args.policy()?;
    let mut source = match &args.pcrs {
        Some(p) => format!("from {}", p.display()),
        None => String::new(),
    };
    if policy.expected.is_none() && !policy.skip_measurement && !args.allow_dev {
        let info = conn.call("GET", "/api/info", None, None).await?;
        let commit = info["source_commit"].as_str().unwrap_or("");
        if info["mode"] == "dev" {
            bail!("this is a dev-mode server: nothing is attested (pass --allow-dev to accept it anyway)");
        }
        if commit.len() != 40 || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("the server reported no source commit; pass --pcrs");
        }
        let url = format!(
            "https://raw.githubusercontent.com/{measurements_repo}/main/measurements/{commit}.pcrs.json"
        );
        let body = https_get(&url)
            .await
            .with_context(|| format!("fetching published measurements for {commit} (or pass --pcrs)"))?;
        policy.expected = Some(ExpectedPcrs::from_json(std::str::from_utf8(&body)?)?);
        source = format!("published in github.com/{measurements_repo} for commit {}", &commit[..12]);
    }
    Ok((policy, source))
}

pub async fn open(
    link: &str,
    port: u16,
    no_browser: bool,
    measurements_repo: &str,
    args: &PolicyArgs,
) -> Result<()> {
    let u = url::Url::parse(link).context("link")?;
    let mut base = u.clone();
    base.set_path("/");
    base.set_query(None);
    base.set_fragment(None);
    let mut conn = Conn::open(&base).await?;

    let (policy, source) = expected_policy(&mut conn, measurements_repo, args).await?;

    let v = conn.attest(&policy).await?;
    crate::print_enclave(&v);
    if !source.is_empty() {
        println!("expected  measurements {source}");
    }
    let pcr0 = v.doc.as_ref().map(|d| d.pcr_hex(0));

    // The app page, from the checked enclave, with a note telling it that it
    // runs behind this client.
    let (status, _, page) = conn.raw("GET", "/", &[], Bytes::new()).await?;
    if status != 200 {
        bail!("GET / returned HTTP {status}");
    }
    let page = String::from_utf8(page.to_vec())?;
    let origin = base.as_str().trim_end_matches('/').to_string();
    let note = json!({
        "origin": origin,
        "pcr0": pcr0,
        "source_commit": v.info.source_commit,
        "boot_id": v.info.boot_id,
        "measurements": source,
        "mode": v.info.mode,
    });
    let note = serde_json::to_string(&note)?.replace('<', "\\u003c");
    let index = page.replacen(
        "<head>",
        &format!("<head>\n<script>window.ATTEST_LOCAL = {note};</script>"),
        1,
    );

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    let local_port = listener.local_addr()?.port();
    let state = Arc::new(State {
        base,
        policy,
        idle: Mutex::new(vec![conn]),
        failed: AtomicBool::new(false),
        pcr0,
        index,
        local_host: format!("127.0.0.1:{local_port}"),
    });

    let path = match u.path().strip_prefix("/s/") {
        Some(id) if !id.is_empty() => format!("/s/{id}"),
        _ => "/".into(),
    };
    let local = format!(
        "http://127.0.0.1:{local_port}{path}{}",
        u.fragment().map(|f| format!("#{f}")).unwrap_or_default()
    );
    println!("\nopen      {local}");
    println!("          (keep this running; Ctrl-C stops it)");
    if !no_browser {
        let opener = if cfg!(target_os = "macos") { "open" } else { "xdg-open" };
        let _ = std::process::Command::new(opener)
            .arg(&local)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    }

    loop {
        let (tcp, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |req| {
                let state = state.clone();
                async move { Ok::<_, std::convert::Infallible>(handle(&state, req).await) }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(tcp), svc)
                .await;
        });
    }
}

fn reply(status: u16, ctype: &str, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
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

fn error(status: u16, msg: &str) -> Response<Full<Bytes>> {
    reply(status, "application/json", json!({"error": msg}).to_string())
}

async fn handle(state: &State, req: Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
    // Only this page may use the client: other sites (DNS rebinding, or
    // cross-origin requests from any tab) are turned away.
    let header = |n: &str| req.headers().get(n).and_then(|v| v.to_str().ok()).map(str::to_string);
    let host_ok = header("host").is_some_and(|h| {
        h == state.local_host || h == state.local_host.replace("127.0.0.1", "localhost")
    });
    let origin_ok = header("origin").map_or(true, |o| {
        o == format!("http://{}", state.local_host)
            || o == format!("http://{}", state.local_host.replace("127.0.0.1", "localhost"))
    });
    if !host_ok || !origin_ok {
        return error(403, "this local client only serves its own page");
    }
    if state.failed.load(Ordering::SeqCst) {
        return error(502, "a check of the enclave failed; this client stopped relaying (see its terminal)");
    }
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();
    let path_q = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| path.clone());
    let is_page = method == "GET"
        && (path == "/" || path.strip_prefix("/s/").is_some_and(|id| !id.is_empty() && !id.contains('/')));
    if is_page {
        return reply(200, "text/html; charset=utf-8", state.index.clone());
    }
    let relayed = (method == "GET" && (path == "/agents.md" || path == "/llms.txt"))
        || (path.starts_with("/api/") && !path.starts_with("/api/internal/"));
    if !relayed {
        return error(404, "not found");
    }
    let auth = header("authorization");
    let ctype = header("content-type");
    let body = match Limited::new(req.into_body(), MAX_BODY).collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => return error(413, "request too large"),
    };
    let mut headers: Vec<(&str, &str)> = Vec::new();
    if let Some(a) = &auth {
        headers.push(("authorization", a));
    }
    if let Some(c) = &ctype {
        headers.push(("content-type", c));
    }
    match relay(state, &method, &path_q, &headers, body).await {
        Ok((status, ctype, body)) => reply(
            status,
            ctype.as_deref().unwrap_or("application/octet-stream"),
            body,
        ),
        Err(e) => error(502, &format!("{e:#}")),
    }
}

/// Sends one request over an attested connection: an idle one, or a new one
/// checked first.
async fn relay(
    state: &State,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Bytes,
) -> Result<(u16, Option<String>, Bytes)> {
    let reused = state.idle.lock().await.pop();
    let mut conn = match reused {
        Some(c) => c,
        None => new_conn(state).await?,
    };
    let r = match conn.raw(method, path, headers, body.clone()).await {
        Ok(r) => r,
        // An idle connection the server closed: retry once on a fresh one.
        // Nothing was sent if the connection was already closed.
        Err(_) if conn.sender.is_closed() || method == "GET" => {
            conn = new_conn(state).await?;
            conn.raw(method, path, headers, body).await?
        }
        Err(e) => return Err(e),
    };
    state.idle.lock().await.push(conn);
    Ok(r)
}

async fn new_conn(state: &State) -> Result<Conn> {
    let mut c = Conn::open(&state.base).await?;
    match c.attest(&state.policy).await {
        Ok(v) => {
            let pcr0 = v.doc.as_ref().map(|d| d.pcr_hex(0));
            if pcr0 != state.pcr0 {
                // Allowed by the policy (e.g. --skip-measurement), but say so.
                eprintln!("note: a new connection reached an enclave with PCR0 {pcr0:?}");
            }
            Ok(c)
        }
        Err(e) => {
            state.failed.store(true, Ordering::SeqCst);
            eprintln!("\nATTESTATION CHECK FAILED on a new connection: {e:#}\nStopped relaying. Don't trust what the page shows from now on.");
            Err(anyhow!("attestation check failed: {e:#}"))
        }
    }
}

/// GET over ordinary web PKI (for published measurements).
pub async fn https_get(url: &str) -> Result<Vec<u8>> {
    let u = url::Url::parse(url)?;
    let host = u.host_str().ok_or_else(|| anyhow!("no host"))?.to_string();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect((host.as_str(), 443)).await?;
    let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(rustls::pki_types::ServerName::try_from(host.clone())?, tcp)
        .await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
    tokio::spawn(conn);
    let req = Request::builder()
        .uri(u.path())
        .header("host", &host)
        .header("user-agent", "attest-cli")
        .body(Full::new(Bytes::new()))?;
    let resp = sender.send_request(req).await?;
    let status = resp.status();
    let body = resp.into_body().collect().await?.to_bytes();
    if !status.is_success() {
        bail!("{url}: HTTP {}", status.as_u16());
    }
    Ok(body.to_vec())
}
