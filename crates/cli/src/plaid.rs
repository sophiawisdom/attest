//! `attest plaid-link`: get a Plaid access token for your own bank account,
//! with your own Plaid keys, on your own computer. It serves Plaid Link on
//! 127.0.0.1, you sign in to your bank in it, and it prints the access
//! token to paste into a session's "Connect tools". Nothing goes to attest.

use anyhow::{bail, ensure, Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// POST JSON to Plaid (`base` is https://ENV.plaid.com, or a test server).
async fn post(base: &url::Url, path: &str, body: Value) -> Result<Value> {
    let host = base.host_str().context("no host")?.to_string();
    let port = base.port_or_known_default().unwrap_or(443);
    let tcp = tokio::net::TcpStream::connect((host.as_str(), port)).await.with_context(|| format!("connecting to {host}"))?;
    let req = hyper::Request::builder()
        .method("POST")
        .uri(path)
        .header("host", &host)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(serde_json::to_vec(&body)?)))?;
    let resp = if base.scheme() == "https" {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(rustls::pki_types::ServerName::try_from(host.clone())?, tcp).await?;
        let (mut s, c) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
        tokio::spawn(c);
        s.send_request(req).await?
    } else {
        let (mut s, c) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
        tokio::spawn(c);
        s.send_request(req).await?
    };
    let status = resp.status();
    let v: Value = serde_json::from_slice(&resp.into_body().collect().await?.to_bytes()).unwrap_or(Value::Null);
    if !status.is_success() {
        bail!("Plaid said: {} ({})", v["error_message"].as_str().unwrap_or("unknown error"), v["error_code"].as_str().unwrap_or(status.as_str()));
    }
    Ok(v)
}

const PAGE: &str = r#"<!doctype html><meta charset="utf-8"><title>Connect your bank</title>
<style>body{font:16px system-ui;max-width:560px;margin:60px auto;padding:0 16px;color:#222}code{background:#eee;padding:2px 4px}</style>
<h2>Connect your bank with Plaid</h2><p id="s">Opening Plaid…</p>
<script src="https://cdn.plaid.com/link/v2/stable/link-initialize.js"></script>
<script>
const s = document.getElementById("s");
const h = Plaid.create({
  token: "LINK_TOKEN",
  onSuccess: (public_token, meta) => {
    s.textContent = "Getting the access token…";
    fetch("/done", {method: "POST", body: public_token}).then(r => r.text()).then(t => s.textContent = t);
  },
  onExit: (err) => { s.textContent = err ? "Plaid stopped: " + (err.display_message || err.error_message || err.error_code) + ". Reload to try again." : "Closed. Reload to try again."; },
});
h.open();
</script>"#;

pub async fn link(client_id: &str, secret: &str, environment: &str, products: &str, port: u16, no_browser: bool, plaid_url: Option<String>) -> Result<()> {
    ensure!(["production", "sandbox"].contains(&environment), "--environment is production or sandbox");
    let base = url::Url::parse(&plaid_url.unwrap_or_else(|| format!("https://{environment}.plaid.com")))?;
    let products: Vec<&str> = products.split(',').map(str::trim).filter(|p| !p.is_empty()).collect();
    let mut user = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut user);
    let mut req = json!({
        "client_id": client_id,
        "secret": secret,
        "client_name": "attest",
        "language": "en",
        "country_codes": ["US", "CA"],
        "user": {"client_user_id": hex::encode(user)},
        "products": products,
    });
    if products.contains(&"transactions") {
        req["transactions"] = json!({"days_requested": 730});
    }
    let lt = post(&base, "/link/token/create", req).await?;
    let link_token = lt["link_token"].as_str().context("Plaid gave no link token")?.to_string();

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    let addr = format!("http://127.0.0.1:{}", listener.local_addr()?.port());
    eprintln!("Open {addr} and sign in to your bank in the Plaid window.");
    if !no_browser {
        let opener = if cfg!(target_os = "macos") { "open" } else { "xdg-open" };
        let _ = std::process::Command::new(opener).arg(&addr).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn();
    }
    loop {
        let (mut sock, _) = listener.accept().await?;
        // One small request at a time: the page, or the public token.
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let (head, body) = loop {
            let n = sock.read(&mut chunk).await?;
            if n == 0 {
                break (String::new(), Vec::new());
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..i]).into_owned();
                let len: usize = head
                    .lines()
                    .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap_or(0)))
                    .unwrap_or(0)
                    .min(4096);
                let mut body = buf[i + 4..].to_vec();
                while body.len() < len {
                    let n = sock.read(&mut chunk).await?;
                    if n == 0 {
                        break;
                    }
                    body.extend_from_slice(&chunk[..n]);
                }
                break (head, body);
            }
            if buf.len() > 16384 {
                break (String::new(), Vec::new());
            }
        };
        let first = head.lines().next().unwrap_or("").to_string();
        let reply = |status: &str, ctype: &str, body: String| {
            format!("HTTP/1.1 {status}\r\ncontent-type: {ctype}\r\ncontent-length: {}\r\ncache-control: no-store\r\nconnection: close\r\n\r\n{body}", body.len())
        };
        if first.starts_with("GET / ") {
            sock.write_all(reply("200 OK", "text/html; charset=utf-8", PAGE.replace("LINK_TOKEN", &link_token)).as_bytes()).await?;
        } else if first.starts_with("POST /done ") {
            let public_token = String::from_utf8_lossy(&body).trim().to_string();
            let r = post(&base, "/item/public_token/exchange", json!({"client_id": client_id, "secret": secret, "public_token": public_token})).await;
            let (msg, done) = match &r {
                Ok(v) => match v["access_token"].as_str() {
                    Some(t) => {
                        let accounts = post(&base, "/accounts/get", json!({"client_id": client_id, "secret": secret, "access_token": t})).await.ok();
                        println!("\nAccess token (paste it into Connect tools → Plaid, with environment {environment}):\n\n  {t}\n");
                        if let Some(a) = accounts {
                            for acc in a["accounts"].as_array().cloned().unwrap_or_default() {
                                println!("  account: {} ({} {}, ••{})", acc["name"].as_str().unwrap_or("?"), acc["type"].as_str().unwrap_or(""), acc["subtype"].as_str().unwrap_or(""), acc["mask"].as_str().unwrap_or("?"));
                            }
                        }
                        println!("\nAnyone with this token and your Plaid keys can read these accounts. When you're done, rotate your secret in the Plaid dashboard (Developers → Keys).");
                        ("Done. The access token is in your terminal; you can close this tab.".to_string(), true)
                    }
                    None => ("Plaid gave no access token.".to_string(), false),
                },
                Err(e) => (format!("{e:#}"), false),
            };
            sock.write_all(reply("200 OK", "text/plain; charset=utf-8", msg.clone()).as_bytes()).await?;
            if done {
                return Ok(());
            }
            eprintln!("{msg}");
        } else {
            sock.write_all(reply("404 Not Found", "text/plain", "not found".into()).as_bytes()).await?;
        }
    }
}
