//! Untrusted parent-instance daemon. Not part of the trusted base: TLS ends
//! inside the enclave, so this only moves ciphertext.
//!
//!   TCP :443              -> enclave vsock 5000   (HTTPS, terminated in the enclave)
//!   vsock 5001 CONNECT    -> TCP host:443          (enclave's outbound TLS)
//!   vsock 5002            -> boot config JSON      (domain, email API key)
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
    // Minimal sanity check without a JSON dependency.
    let t = String::from_utf8_lossy(b);
    if !t.trim_start().starts_with('{') {
        bail!("config must be a JSON object");
    }
    Ok(())
}
