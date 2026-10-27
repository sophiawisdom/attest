//! Untrusted parent-instance daemon. It is not part of the trusted base:
//! submissions are encrypted to the enclave, results to the auditee, and
//! everything the enclave says is signed. It does two things:
//!
//!   * TCP :8080           -> enclave vsock 5000   (client API)
//!   * vsock 5001 CONNECT  -> TCP host:443          (inference calls; TLS ends in the enclave)
//!
//! The tunnel allowlist here is defense in depth; the enclave enforces its
//! own fixed endpoints.

use anyhow::{bail, Context, Result};
use clap::Parser;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

const ALLOWED: &[&str] = &["api.openai.com", "api.anthropic.com", "openrouter.ai"];

#[derive(Parser, Debug, Clone)]
#[command(name = "attest-host")]
struct Args {
    /// Loopback TCP instead of vsock; also allows tunnels to 127.0.0.1 (mock provider).
    #[arg(long)]
    dev: bool,
    #[arg(long, default_value = "0.0.0.0:8080")]
    listen: String,
    #[arg(long, default_value_t = 16)]
    enclave_cid: u32,
    #[arg(long, default_value_t = 5000)]
    enclave_port: u32,
    #[arg(long, default_value_t = 5001)]
    tunnel_port: u32,
    /// Dev only: enclave API address.
    #[arg(long, default_value = "127.0.0.1:5000")]
    dev_enclave: String,
    /// Dev only: address to accept tunnel requests on.
    #[arg(long, default_value = "127.0.0.1:5001")]
    dev_tunnel: String,
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

fn log(m: &str) {
    eprintln!("[attest-host] {m}");
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let a = args.clone();
    let tunnel = tokio::spawn(async move { tunnel_server(a).await });
    let fwd = tokio::spawn(async move { forward_server(args).await });
    tokio::select! {
        r = tunnel => r??,
        r = fwd => r??,
    }
    Ok(())
}

async fn dial_enclave(args: &Args) -> Result<Box<dyn Io>> {
    if args.dev {
        return Ok(Box::new(TcpStream::connect(&args.dev_enclave).await?));
    }
    #[cfg(target_os = "linux")]
    {
        let s = tokio_vsock::VsockStream::connect(tokio_vsock::VsockAddr::new(args.enclave_cid, args.enclave_port)).await?;
        Ok(Box::new(s))
    }
    #[cfg(not(target_os = "linux"))]
    bail!("vsock requires linux; use --dev")
}

async fn forward_server(args: Args) -> Result<()> {
    let l = TcpListener::bind(&args.listen).await.with_context(|| format!("binding {}", args.listen))?;
    log(&format!("forwarding {} -> enclave", args.listen));
    loop {
        let (mut client, peer) = l.accept().await?;
        let args = args.clone();
        tokio::spawn(async move {
            match dial_enclave(&args).await {
                Ok(mut e) => {
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut e).await;
                }
                Err(err) => log(&format!("{peer}: enclave unreachable: {err:#}")),
            }
        });
    }
}

fn allowed(args: &Args, host: &str, port: u16) -> bool {
    if ALLOWED.contains(&host) && port == 443 {
        return true;
    }
    args.dev && (host == "127.0.0.1" || host == "localhost")
}

async fn handle_tunnel<S: Io>(args: Args, s: S) -> Result<()> {
    let mut r = BufReader::new(s);
    let mut line = String::new();
    r.read_line(&mut line).await?;
    let target = line.trim().strip_prefix("CONNECT ").context("expected CONNECT")?.to_string();
    let (host, port) = target.rsplit_once(':').context("expected host:port")?;
    let port: u16 = port.parse()?;
    if !allowed(&args, host, port) {
        r.get_mut().write_all(b"ERR destination not allowed\n").await?;
        bail!("refused tunnel to {target}");
    }
    let mut up = match TcpStream::connect((host, port)).await {
        Ok(u) => u,
        Err(e) => {
            r.get_mut().write_all(format!("ERR {e}\n").as_bytes()).await?;
            return Err(e.into());
        }
    };
    r.get_mut().write_all(b"OK\n").await?;
    // Nothing follows the CONNECT line until our OK, so the buffer is empty.
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
