//! attest CLI: verify the service, upload code into a session, verify
//! certificates. Everything else happens in the web app or over the HTTP API
//! (see /agents.md on any attest server).

mod bundle;
mod local;
mod plaid;
mod rebuild;

use anyhow::{anyhow, bail, Context, Result};
use attest_core::nitro::ExpectedPcrs;
use attest_core::verify::{verify_certificate, verify_enclave, EnclavePolicy, VerifiedEnclave};
use attest_core::*;
use bytes::Bytes;
use clap::{Args, Parser, Subcommand};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Parser)]
#[command(
    name = "attest",
    about = "Attested LLM code audits. See /agents.md on the server for the protocol."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args, Clone)]
struct PolicyArgs {
    /// Expected enclave measurements (nitro-cli build output, e.g. measurements/*.pcrs.json).
    #[arg(long)]
    pcrs: Option<PathBuf>,
    /// Accept a dev-mode server (proves nothing; for testing).
    #[arg(long)]
    allow_dev: bool,
    /// Accept any genuine Nitro enclave without checking which build it runs.
    #[arg(long)]
    skip_measurement: bool,
}

impl PolicyArgs {
    fn policy(&self) -> Result<EnclavePolicy> {
        let expected = match &self.pcrs {
            Some(p) => Some(ExpectedPcrs::from_json(
                &std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?,
            )?),
            None => None,
        };
        Ok(EnclavePolicy {
            expected,
            allow_dev: self.allow_dev,
            skip_measurement: self.skip_measurement,
        })
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Check that a server is a genuine attest enclave running the expected build,
    /// and that TLS to it terminates inside that enclave.
    VerifyService {
        url: String,
        /// Where to fetch published measurements when --pcrs isn't given
        /// (a GitHub owner/repo with a measurements/ directory).
        #[arg(long, default_value = local::MEASUREMENTS_REPO)]
        measurements_repo: String,
        /// Build the enclave image from the server's source commit here
        /// (needs docker and nitro-cli) and check the server against that,
        /// instead of trusting the published measurements.
        #[arg(long)]
        rebuild: bool,
        /// With --rebuild: build with no caches.
        #[arg(long)]
        fresh: bool,
        /// With --rebuild: where to fetch the source.
        #[arg(long, default_value = "https://github.com/sophiawisdom/attest")]
        source_repo: String,
        #[command(flatten)]
        policy: PolicyArgs,
        #[arg(long)]
        json: bool,
    },
    /// Auditee: upload a repository into a session (git-tracked files only),
    /// after verifying the server.
    Upload {
        /// Your auditee session link (https://HOST/s/ID#TOKEN).
        link: String,
        dir: PathBuf,
        /// Recorded as where you say the code comes from (the enclave can't
        /// check an upload; import from GitHub for a checked record).
        /// Defaults to `git remote get-url origin`.
        #[arg(long)]
        repo_url: Option<String>,
        /// Defaults to `git rev-parse HEAD`.
        #[arg(long)]
        git_commit: Option<String>,
        /// Upload even if tracked files have uncommitted changes.
        #[arg(long)]
        allow_dirty: bool,
        #[command(flatten)]
        policy: PolicyArgs,
    },
    /// Auditee: get a Plaid access token for your bank account, to paste
    /// into a session's "Connect tools" → Plaid. Uses your own Plaid keys
    /// (a free Trial account works with real banks), runs Plaid Link on
    /// 127.0.0.1, and prints the token. Nothing is sent to attest.
    PlaidLink {
        #[arg(long, env = "PLAID_CLIENT_ID")]
        client_id: String,
        /// Your Plaid secret for the environment (best set in PLAID_SECRET).
        #[arg(long, env = "PLAID_SECRET", hide_env_values = true)]
        secret: String,
        /// production (real banks; the Trial plan's keys) or sandbox.
        #[arg(long, default_value = "production")]
        environment: String,
        /// Plaid products to request, comma-separated.
        #[arg(long, default_value = "transactions")]
        products: String,
        #[arg(long, default_value_t = 0)]
        port: u16,
        #[arg(long)]
        no_browser: bool,
        /// Testing only: Plaid's API at another address.
        #[arg(long, hide = true)]
        plaid_url: Option<String>,
    },
    /// Open a session in your browser through a local client: it checks the
    /// enclave's attestation, serves the web app on 127.0.0.1, and sends every
    /// API call over TLS sessions it has checked end inside that enclave.
    Open {
        /// A session link (https://HOST/s/ID#TOKEN) or the server's URL.
        link: String,
        /// Local port (default: any free port).
        #[arg(long, default_value_t = 0)]
        port: u16,
        /// Print the local link instead of opening a browser.
        #[arg(long)]
        no_browser: bool,
        /// Where to fetch published measurements when --pcrs isn't given
        /// (a GitHub owner/repo with a measurements/ directory).
        #[arg(long, default_value = local::MEASUREMENTS_REPO)]
        measurements_repo: String,
        #[command(flatten)]
        policy: PolicyArgs,
    },
    /// Verify a certificate or a disclosure offline.
    Verify {
        certificate: PathBuf,
        #[command(flatten)]
        policy: PolicyArgs,
        #[arg(long)]
        json: bool,
    },
}

// ------------------------------------------------------------------ connection

/// Accepts any server certificate but records it: trust comes from the
/// attestation, which must name this certificate's key.
#[derive(Debug)]
struct Capture {
    provider: Arc<rustls::crypto::CryptoProvider>,
    cert: Mutex<Option<Vec<u8>>>,
}

impl ServerCertVerifier for Capture {
    fn verify_server_cert(
        &self,
        end: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.cert.lock().unwrap() = Some(end.to_vec());
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            m,
            c,
            d,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            m,
            c,
            d,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// One HTTP/1.1 connection, kept open so the attestation check and the
/// requests that rely on it happen over the same TLS session.
struct Conn {
    sender: SendRequest<Full<Bytes>>,
    host: String,
    spki_sha256: Option<String>,
}

impl Conn {
    async fn open(base: &url::Url) -> Result<Self> {
        let host = base
            .host_str()
            .ok_or_else(|| anyhow!("URL has no host"))?
            .to_string();
        let https = base.scheme() == "https";
        let port = base.port_or_known_default().unwrap_or(443);
        let tcp = tokio::net::TcpStream::connect((host.as_str(), port))
            .await
            .with_context(|| format!("connecting to {host}:{port}"))?;
        let host_header = match base.port() {
            Some(p) => format!("{host}:{p}"),
            None => host.clone(),
        };
        if !https {
            let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
            tokio::spawn(conn);
            return Ok(Self {
                sender,
                host: host_header,
                spki_sha256: None,
            });
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let capture = Arc::new(Capture {
            provider: provider.clone(),
            cert: Mutex::new(None),
        });
        let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(capture.clone())
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let name = ServerName::try_from(host.clone())?;
        let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
            .connect(name, tcp)
            .await
            .context("TLS handshake")?;
        let cert = capture
            .cert
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| anyhow!("server sent no certificate"))?;
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
        tokio::spawn(conn);
        Ok(Self {
            sender,
            host: host_header,
            spki_sha256: Some(spki_sha256_of_cert(&cert)?),
        })
    }

    /// One request, returned as is: status, content type and body.
    async fn raw(
        &mut self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Bytes,
    ) -> Result<(u16, Option<String>, Bytes)> {
        let mut req = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header("host", &self.host);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        self.sender.ready().await?;
        let resp = self.sender.send_request(req.body(Full::new(body))?).await?;
        let status = resp.status().as_u16();
        let ctype = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        Ok((status, ctype, resp.into_body().collect().await?.to_bytes()))
    }

    async fn call(
        &mut self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<(Vec<u8>, &str)>,
    ) -> Result<Value> {
        self.call_with(method, path, token, body, &[]).await
    }

    async fn call_with(
        &mut self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<(Vec<u8>, &str)>,
        headers: &[(&str, String)],
    ) -> Result<Value> {
        let mut req = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header("host", &self.host);
        for (k, v) in headers {
            req = req.header(*k, v);
        }
        if let Some(t) = token {
            req = req.header("authorization", format!("Bearer {t}"));
        }
        let body = match body {
            Some((b, ctype)) => {
                req = req.header("content-type", ctype);
                Full::new(Bytes::from(b))
            }
            None => Full::new(Bytes::new()),
        };
        // The connection is ready for the next request only once the
        // previous exchange has fully finished on it.
        self.sender.ready().await?;
        let resp = self.sender.send_request(req.body(body)?).await?;
        let status = resp.status();
        let bytes = resp.into_body().collect().await?.to_bytes();
        let v: Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({"error": String::from_utf8_lossy(&bytes)}));
        if !status.is_success() {
            bail!(
                "{method} {path}: HTTP {}: {}",
                status.as_u16(),
                v["error"].as_str().unwrap_or("error")
            );
        }
        Ok(v)
    }

    /// Fresh attestation, checked against the policy, and bound to this TLS session.
    async fn attest(&mut self, policy: &EnclavePolicy) -> Result<VerifiedEnclave> {
        let nonce: [u8; 32] = rand::random();
        let v = self
            .call(
                "GET",
                &format!("/api/attestation?nonce={}", hex::encode(nonce)),
                None,
                None,
            )
            .await?;
        let a: AttestationResponse = serde_json::from_value(v)?;
        let ve = verify_enclave(
            &a.enclave_info_json,
            a.document_b64.as_deref(),
            Some(&nonce),
            policy,
        )?;
        if ve.info.mode == "nitro" {
            let want = ve
                .info
                .tls_spki_sha256
                .as_deref()
                .ok_or_else(|| anyhow!("enclave did not commit to a TLS key"))?;
            let got = self
                .spki_sha256
                .as_deref()
                .ok_or_else(|| anyhow!("a Nitro enclave must be reached over https"))?;
            if want != got {
                bail!("TLS does not terminate in the attested enclave (server key {got}, attested {want}): something is in between");
            }
        }
        Ok(ve)
    }
}

fn print_enclave(v: &VerifiedEnclave) {
    let i = &v.info;
    match &v.doc {
        Some(d) => println!("verified: AWS Nitro enclave, PCR0 {}", d.pcr_hex(0)),
        None => println!("DEV MODE: nothing is attested"),
    }
    println!("source    {} @ {}", i.source_repo, i.source_commit);
    println!(
        "boot      {} ({} ms since epoch)",
        i.boot_id, i.booted_at_ms
    );
    if let Some(s) = &i.tls_spki_sha256 {
        println!("TLS key   {s} (this connection terminates inside the enclave)");
    }
    println!(
        "harness   {} prompt {}",
        i.harness.version, i.harness.system_prompt_sha256
    );
    for w in &v.warnings {
        println!("warning   {w}");
    }
}

// ------------------------------------------------------------------ commands

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::VerifyService { url, measurements_repo, rebuild, fresh, source_repo, mut policy, json } => {
            let base = url::Url::parse(&url).context("URL")?;
            let mut c = Conn::open(&base).await?;
            let mut rebuilt_note = String::new();
            if rebuild {
                if policy.pcrs.is_some() {
                    bail!("--rebuild makes its own measurements; drop --pcrs");
                }
                let info = c.call("GET", "/api/info", None, None).await?;
                let commit = info["source_commit"].as_str().unwrap_or("").to_string();
                if commit.len() != 40 || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
                    bail!("the server reported no source commit to rebuild");
                }
                let path = rebuild::build(&source_repo, &commit, fresh)?;
                let mine = rebuild::pcrs(&std::fs::read_to_string(&path)?)?;
                // Also say whether what was published matches, so a mismatch
                // points at the publisher or at the build.
                let url = format!("https://raw.githubusercontent.com/{measurements_repo}/main/measurements/{commit}.pcrs.json");
                let published = match local::https_get(&url).await {
                    Ok(b) => match rebuild::pcrs(std::str::from_utf8(&b)?) {
                        Ok(p) if p == mine => "the published measurements match this build".to_string(),
                        Ok(_) => "the published measurements DIFFER from this build".to_string(),
                        Err(e) => format!("the published measurements don't parse: {e}"),
                    },
                    Err(_) => "no measurements are published for this commit".to_string(),
                };
                rebuilt_note = format!("built here from {source_repo} at {} ({}); {published}", &commit[..12], path.display());
                policy.pcrs = Some(path);
                // The build takes minutes: the first connection is long gone.
                c = Conn::open(&base).await?;
            }
            let (expected, mut source) = local::expected_policy(&mut c, &measurements_repo, &policy).await?;
            if rebuild {
                source = rebuilt_note;
            }
            let v = c.attest(&expected).await?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &json!({"info": v.info, "pcr0": v.doc.as_ref().map(|d| d.pcr_hex(0)), "warnings": v.warnings})
                    )?
                );
            } else {
                print_enclave(&v);
                if !source.is_empty() {
                    println!("expected  measurements {source}");
                }
            }
        }

        Cmd::Upload {
            link,
            dir,
            repo_url,
            git_commit,
            allow_dirty,
            policy,
        } => {
            let u = url::Url::parse(&link).context("link")?;
            let token = u
                .fragment()
                .filter(|t| !t.is_empty())
                .ok_or_else(|| anyhow!("the link has no token after #"))?
                .to_string();
            let sid = u
                .path()
                .strip_prefix("/s/")
                .ok_or_else(|| anyhow!("not a session link (expected /s/ID#TOKEN)"))?
                .to_string();
            let git = bundle::git_info(&dir);
            if git.dirty && !allow_dirty {
                bail!("{} has uncommitted changes to tracked files; commit them or pass --allow-dirty", dir.display());
            }
            let files = bundle::collect(&dir)?;
            let (tar, tree) = bundle::tar_and_hash(&files)?;
            let total: usize = files.iter().map(|(_, b)| b.len()).sum();

            let mut c = Conn::open(&u).await?;
            let v = c.attest(&policy.policy()?).await?;
            print_enclave(&v);
            let view = c
                .call("GET", &format!("/api/sessions/{sid}"), Some(&token), None)
                .await?;
            if view["role"] != "auditee" {
                bail!("this is not an auditee link");
            }
            eprintln!(
                "uploading {} files, {} bytes, tree {tree}",
                files.len(),
                total
            );
            let mut claims = Vec::new();
            if let Some(u) = repo_url.or(git.remote) {
                claims.push(("x-attest-repo-url", u));
            }
            if let Some(h) = git_commit.or(git.head) {
                claims.push(("x-attest-git-commit", h));
            }
            let r = c
                .call_with(
                    "PUT",
                    &format!("/api/sessions/{sid}/code"),
                    Some(&token),
                    Some((tar, "application/x-tar")),
                    &claims,
                )
                .await?;
            if r["tree_sha256"] != json!(tree) {
                bail!(
                    "the enclave computed tree {} but the local tree is {tree}",
                    r["tree_sha256"]
                );
            }
            println!("uploaded: tree {tree} ({} files)", files.len());
        }

        Cmd::PlaidLink { client_id, secret, environment, products, port, no_browser, plaid_url } => {
            plaid::link(&client_id, &secret, &environment, &products, port, no_browser, plaid_url).await?
        }
        Cmd::Open {
            link,
            port,
            no_browser,
            measurements_repo,
            policy,
        } => local::open(&link, port, no_browser, &measurements_repo, &policy).await?,

        Cmd::Verify {
            certificate,
            policy,
            json,
        } => {
            let raw = std::fs::read_to_string(&certificate)?;
            let probe: Value = serde_json::from_str(&raw).context("JSON")?;
            if probe["signed"]["domain"] == json!(attest_core::DOMAIN_DISCLOSURE) {
                let d: attest_core::Disclosure =
                    serde_json::from_value(probe).context("disclosure JSON")?;
                let v = attest_core::verify::verify_disclosure(&d, &policy.policy()?)?;
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &json!({"body": v.body, "enclave_warnings": v.enclave.warnings})
                        )?
                    );
                    return Ok(());
                }
                print_enclave(&v.enclave);
                let b = &v.body;
                println!();
                println!(
                    "disclosure #{} in session {}, code commitment {}",
                    b.number, b.session_id, b.code_commitment_sha256
                );
                if let Some(n) = &b.note {
                    println!("note: {n}");
                }
                match &b.content {
                    attest_core::DisclosureContent::File {
                        path,
                        size,
                        sha256,
                        text,
                        ..
                    } => {
                        println!("file {path} ({size} bytes, sha256 {sha256})\n");
                        match text {
                            Some(t) => print!("{t}"),
                            None => println!("(binary; see --json)"),
                        }
                    }
                    attest_core::DisclosureContent::Python {
                        code,
                        stdout,
                        stderr,
                        exit_code,
                        timed_out,
                        files_opened,
                        ..
                    } => {
                        println!("script ({} files opened, exit {:?}{}):\n{code}\n--- stdout ---\n{stdout}", files_opened.len(), exit_code, if *timed_out { ", timed out" } else { "" });
                        if !stderr.is_empty() {
                            println!("--- stderr ---\n{stderr}");
                        }
                    }
                }
                return Ok(());
            }
            let cert: Certificate = serde_json::from_str(&raw).context("certificate JSON")?;
            let v = verify_certificate(&cert, &policy.policy()?)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &json!({"body": v.body, "flags": v.warnings, "enclave_warnings": v.enclave.warnings})
                    )?
                );
                return Ok(());
            }
            print_enclave(&v.enclave);
            let m = &v.body.manifest;
            println!();
            println!(
                "session   {} run {} (#{})",
                m.session_id, m.run_id, m.run_number
            );
            println!("question  v{}: {}", m.question.version, m.question.text);
            if m.has_code {
                println!("code      {}", m.affidavit.statement);
            }
            for c in &m.connections {
                println!(
                    "connected {} ({}): {}",
                    c.name,
                    c.hosts.join(", "),
                    c.identity.as_deref().unwrap_or("owner not verified")
                );
            }
            if m.verdict_only() {
                println!("code      commitment {} (not opened: verdict-only release)", m.code.commitment_sha256);
            } else {
                println!(
                    "code      {} files, {} bytes, tree {}",
                    m.code.file_count, m.code.total_bytes, m.code.tree_sha256
                );
            }
            println!(
                "model     {} via {} (chosen by {:?}; reported {}; key owner {})",
                m.model.requested_model,
                m.model.endpoint,
                m.model.proposed_by,
                if m.model.response_models.is_empty() {
                    "-".into()
                } else {
                    m.model.response_models.join(", ")
                },
                m.model.key_owner.as_deref().unwrap_or("not reported")
            );
            if !m.verdict_only() {
                println!(
                    "activity  {} model calls, {} files read, {}+{} tokens",
                    m.activity.llm_calls,
                    m.activity.files_read,
                    m.activity.input_tokens,
                    m.activity.output_tokens
                );
            }
            match &v.body.verdict {
                Some(vd) => {
                    println!(
                        "\nverdict: {:?}\n{}",
                        vd.answer, vd.summary
                    );
                    if let Some(c) = &vd.clarification_request {
                        println!("clarification requested: {c}");
                    }
                }
                None => println!("\nno verdict ({:?})", m.outcome),
            }
            if !v.warnings.is_empty() {
                println!("\nweigh these:");
                for w in &v.warnings {
                    println!("  - {w}");
                }
            }
        }
    }
    Ok(())
}
