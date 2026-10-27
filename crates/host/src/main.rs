//! Untrusted parent-instance daemon. Not part of the trusted base: TLS ends
//! inside the enclave, so this only moves ciphertext.
//!
//!   TCP :443              -> enclave vsock 5000   (HTTPS, terminated in the enclave)
//!   vsock 5001 CONNECT    -> TCP host:443          (enclave's outbound TLS)
//!   vsock 5002            -> boot config JSON      (domain or public IP, email sender)
//!   vsock 5003            -> instance role credentials from IMDSv2 (for SES)
//!   vsock 5004            <- the enclave's operational log lines (printed here)
//!
//! Outbound tunnels may go to any public address on port 443 (webhooks can
//! point anywhere); the enclave decides where it connects.

use anyhow::{bail, Context, Result};
use clap::Parser;
use std::net::IpAddr;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

#[derive(Parser, Debug, Clone)]
#[command(name = "attest-host")]
struct Args {
    /// Loopback TCP instead of vsock; also allows tunnels to loopback (mock provider).
    #[arg(long)]
    dev: bool,
    #[arg(long, default_value = "0.0.0.0:443")]
    listen: String,
    #[arg(long, default_value_t = 16)]
    enclave_cid: u32,
    #[arg(long, default_value_t = 5000)]
    enclave_port: u32,
    #[arg(long, default_value_t = 5001)]
    tunnel_port: u32,
    #[arg(long, default_value_t = 5002)]
    config_port: u32,
    #[arg(long, default_value_t = 5003)]
    credentials_port: u32,
    /// JSON handed to the enclave at boot: {"domain", "email": {"resend_api_key", "from"}, ...}.
    #[arg(long)]
    config: Option<String>,
    /// Dev only: address to accept tunnel requests on.
    #[arg(long, default_value = "127.0.0.1:5001")]
    dev_tunnel: String,
    /// Don't forward inbound connections (dev, where the enclave serves HTTP itself).
    #[arg(long)]
    no_forward: bool,
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

fn log(m: &str) {
    eprintln!("[attest-host] {m}");
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let mut tasks = tokio::task::JoinSet::new();
    let a = args.clone();
    tasks.spawn(async move { tunnel_server(a).await });
    if !args.dev {
        let a = args.clone();
        tasks.spawn(async move { config_server(a).await });
        let a = args.clone();
        tasks.spawn(async move { credentials_server(a).await });
        tasks.spawn(async move { log_server().await });
    }
    if !args.no_forward {
        let a = args.clone();
        tasks.spawn(async move { forward_server(a).await });
    }
    if let Some(r) = tasks.join_next().await {
        r??;
    }
    Ok(())
}

async fn forward_server(args: Args) -> Result<()> {
    let l = TcpListener::bind(&args.listen).await.with_context(|| format!("binding {}", args.listen))?;
    log(&format!("forwarding {} -> enclave", args.listen));
    loop {
        let (mut client, peer) = l.accept().await?;
        let args = args.clone();
        tokio::spawn(async move {
            #[cfg(target_os = "linux")]
            {
                match tokio_vsock::VsockStream::connect(tokio_vsock::VsockAddr::new(args.enclave_cid, args.enclave_port)).await {
                    Ok(mut e) => {
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut e).await;
                    }
                    Err(err) => log(&format!("{peer}: enclave unreachable: {err}")),
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (&mut client, peer, args);
                log("vsock forwarding requires linux");
            }
        });
    }
}

fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => !(v.is_private() || v.is_loopback() || v.is_link_local() || v.is_unspecified() || v.is_broadcast() || v.octets()[0] == 100 && (v.octets()[1] & 0xc0) == 64),
        IpAddr::V6(v) => !(v.is_loopback() || v.is_unspecified() || (v.segments()[0] & 0xfe00) == 0xfc00 || (v.segments()[0] & 0xffc0) == 0xfe80),
    }
}

async fn handle_tunnel<S: Io>(args: Args, s: S) -> Result<()> {
    let mut r = BufReader::new(s);
    let mut line = String::new();
    r.read_line(&mut line).await?;
    let target = line.trim().strip_prefix("CONNECT ").context("expected CONNECT")?.to_string();
    let (host, port) = target.rsplit_once(':').context("expected host:port")?;
    let port: u16 = port.parse()?;
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, port)).await.map(|a| a.collect()).unwrap_or_default();
    let ok_addr = addrs.into_iter().find(|a| (port == 443 && public(a.ip())) || (args.dev && a.ip().is_loopback()));
    let Some(addr) = ok_addr else {
        r.get_mut().write_all(b"ERR destination not allowed\n").await?;
        bail!("refused tunnel to {target}");
    };
    let mut up = match TcpStream::connect(addr).await {
        Ok(u) => u,
        Err(e) => {
            r.get_mut().write_all(format!("ERR {e}\n").as_bytes()).await?;
            return Err(e.into());
        }
    };
    r.get_mut().write_all(b"OK\n").await?;
    let mut s = r.into_inner();
    tokio::io::copy_bidirectional(&mut s, &mut up).await?;
    Ok(())
}

async fn tunnel_server(args: Args) -> Result<()> {
    if args.dev {
        let l = TcpListener::bind(&args.dev_tunnel).await?;
        log(&format!("dev tunnel on {}", args.dev_tunnel));
        loop {
            let (s, _) = l.accept().await?;
            let a = args.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_tunnel(a, s).await {
                    log(&format!("tunnel: {e:#}"));
                }
            });
        }
    }
    #[cfg(target_os = "linux")]
    {
        let l = tokio_vsock::VsockListener::bind(tokio_vsock::VsockAddr::new(tokio_vsock::VMADDR_CID_ANY, args.tunnel_port))?;
        log(&format!("tunnel on vsock {}", args.tunnel_port));
        loop {
            let (s, _) = l.accept().await?;
            let a = args.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_tunnel(a, s).await {
                    log(&format!("tunnel: {e:#}"));
                }
            });
        }
    }
    #[allow(unreachable_code)]
    {
        bail!("vsock requires linux; use --dev")
    }
}

async fn config_server(args: Args) -> Result<()> {
    let body = match &args.config {
        Some(p) => std::fs::read(p).with_context(|| format!("reading {p}"))?,
        None => b"{}".to_vec(),
    };
    serde_json_check(&body)?;
    #[cfg(target_os = "linux")]
    {
        let l = tokio_vsock::VsockListener::bind(tokio_vsock::VsockAddr::new(tokio_vsock::VMADDR_CID_ANY, args.config_port))?;
        log(&format!("config on vsock {}", args.config_port));
        loop {
            let (mut s, _) = l.accept().await?;
            let _ = s.write_all(&body).await;
            let _ = AsyncWriteExt::shutdown(&mut s).await;
        }
    }
    #[allow(unreachable_code)]
    {
        let _ = (body, args.config_port);
        bail!("vsock requires linux")
    }
}

fn serde_json_check(b: &[u8]) -> Result<()> {
    let v: serde_json::Value = serde_json::from_slice(b).context("config is not JSON")?;
    if !v.is_object() {
        bail!("config must be a JSON object");
    }
    Ok(())
}

/// Print the enclave's log lines (it has no console in production).
async fn log_server() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let l = tokio_vsock::VsockListener::bind(tokio_vsock::VsockAddr::new(tokio_vsock::VMADDR_CID_ANY, 5004))?;
        loop {
            let (s, _) = l.accept().await?;
            tokio::spawn(async move {
                let mut lines = BufReader::new(s).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let line: String = line.chars().filter(|c| !c.is_control()).take(2000).collect();
                    eprintln!("{line}");
                }
            });
        }
    }
    #[allow(unreachable_code)]
    {
        bail!("vsock requires linux")
    }
}

/// One plain-HTTP request to the instance metadata service.
async fn imds(method: &str, path: &str, headers: &[(&str, &str)]) -> Result<String> {
    use tokio::io::AsyncReadExt;
    let mut s = tokio::time::timeout(std::time::Duration::from_secs(3), TcpStream::connect("169.254.169.254:80")).await??;
    let mut req = format!("{method} {path} HTTP/1.0\r\nHost: 169.254.169.254\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(3), (&mut s).take(64 * 1024).read_to_end(&mut buf)).await??;
    let text = String::from_utf8_lossy(&buf).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").context("bad IMDS response")?;
    if !head.starts_with("HTTP/1.0 200") && !head.starts_with("HTTP/1.1 200") {
        bail!("IMDS {path}: {}", head.lines().next().unwrap_or(""));
    }
    Ok(body.to_string())
}

async fn role_credentials() -> Result<Vec<u8>> {
    let token = imds("PUT", "/latest/api/token", &[("X-aws-ec2-metadata-token-ttl-seconds", "60")]).await?;
    let h = [("X-aws-ec2-metadata-token", token.trim())];
    let role = imds("GET", "/latest/meta-data/iam/security-credentials/", &h).await?;
    let role = role.lines().next().context("no instance role attached")?.trim().to_string();
    if role.is_empty() || !role.chars().all(|c| c.is_ascii_alphanumeric() || "_+=,.@-".contains(c)) {
        bail!("invalid role name");
    }
    let v: serde_json::Value = serde_json::from_str(&imds("GET", &format!("/latest/meta-data/iam/security-credentials/{role}"), &h).await?)?;
    let out = serde_json::json!({
        "access_key_id": v["AccessKeyId"],
        "secret_access_key": v["SecretAccessKey"],
        "session_token": v["Token"],
    });
    Ok(serde_json::to_vec(&out)?)
}

/// Hands the instance role's temporary credentials to the enclave, which
/// signs its own SES requests over TLS that ends inside it.
async fn credentials_server(args: Args) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let l = tokio_vsock::VsockListener::bind(tokio_vsock::VsockAddr::new(tokio_vsock::VMADDR_CID_ANY, args.credentials_port))?;
        log(&format!("credentials on vsock {}", args.credentials_port));
        loop {
            let (mut s, _) = l.accept().await?;
            tokio::spawn(async move {
                match role_credentials().await {
                    Ok(c) => {
                        let _ = s.write_all(&c).await;
                    }
                    Err(e) => log(&format!("credentials: {e:#}")),
                }
                let _ = AsyncWriteExt::shutdown(&mut s).await;
            });
        }
    }
    #[allow(unreachable_code)]
    {
        let _ = (args.credentials_port, role_credentials);
        bail!("vsock requires linux")
    }
}
