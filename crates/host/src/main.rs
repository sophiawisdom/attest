//! Untrusted parent-instance daemon. Not part of the trusted base: TLS ends
//! inside the enclave, so this only moves ciphertext.
//!
//!   TCP :443              -> enclave vsock 5000   (HTTPS, terminated in the enclave)
//!   vsock 5001 CONNECT    -> TCP host:443          (enclave's outbound TLS)
//!   vsock 5002            -> boot config JSON      (domain or public IP, email sender)
//!   vsock 5003            -> instance role credentials from IMDSv2 (for SES)
//!   vsock 5004            <- the enclave's operational log lines (printed here)
//!   vsock 5005            <-> sealed file store (ciphertext only; the enclave holds the keys)
//!
//! Outbound tunnels may go to any public address on port 443 (webhooks can
//! point anywhere); the enclave decides where it connects.

use anyhow::{bail, Context, Result};
use clap::Parser;
use std::net::IpAddr;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
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
    /// Where sealed files are kept. Kept across restarts of this daemon; wiped
    /// when a new enclave boot says so (the old keys died with the old boot).
    #[arg(long, default_value = "/var/lib/attest/blobs")]
    blob_dir: String,
    /// Disk quota for sealed files.
    #[arg(long, default_value_t = 50)]
    blob_quota_gib: u64,
    /// Dev only: address for the blob store.
    #[arg(long, default_value = "127.0.0.1:5005")]
    dev_blobs: String,
    /// Don't forward inbound connections (dev, where the enclave serves HTTP itself).
    #[arg(long)]
    no_forward: bool,
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

fn log(m: &str) {
    eprintln!("[attest-host] {m}");
}

/// Simultaneous connections per service; more are closed on arrival.
const MAX_FORWARDED: usize = 2048;
const MAX_TUNNELS: usize = 512;
const MAX_BLOB_REQUESTS: usize = 64;
/// Largest stored blob (the enclave's blobs::HOST_MAX_BLOB_BYTES).
const MAX_BLOB_BYTES: u64 = 80 << 20;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let blobs = std::sync::Arc::new(Blobs::open(&args).await?);
    // Each service runs on its own and is restarted if it fails, so one
    // failing listener doesn't take forwarding, tunnels and storage with it.
    let mut tasks = tokio::task::JoinSet::new();
    let a = args.clone();
    tasks.spawn(supervise("tunnel", move || tunnel_server(a.clone())));
    let (a, b) = (args.clone(), blobs.clone());
    tasks.spawn(supervise("blob store", move || blob_server(a.clone(), b.clone())));
    if !args.dev {
        let a = args.clone();
        tasks.spawn(supervise("config", move || config_server(a.clone())));
        let a = args.clone();
        tasks.spawn(supervise("credentials", move || credentials_server(a.clone())));
        tasks.spawn(supervise("log", log_server));
    }
    if !args.no_forward {
        let a = args.clone();
        tasks.spawn(supervise("forwarding", move || forward_server(a.clone())));
    }
    while tasks.join_next().await.is_some() {}
    Ok(())
}

/// Run a service forever, restarting it with backoff when it returns.
async fn supervise<F, Fut>(name: &'static str, start: F)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let mut backoff = std::time::Duration::from_secs(1);
    loop {
        let t = std::time::Instant::now();
        if let Err(e) = start().await {
            log(&format!("{name}: {e:#}; restarting in {backoff:?}"));
        }
        if t.elapsed() > std::time::Duration::from_secs(60) {
            backoff = std::time::Duration::from_secs(1);
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(std::time::Duration::from_secs(30));
    }
}

fn permits(n: usize) -> std::sync::Arc<tokio::sync::Semaphore> {
    std::sync::Arc::new(tokio::sync::Semaphore::new(n))
}

async fn forward_server(args: Args) -> Result<()> {
    let l = TcpListener::bind(&args.listen)
        .await
        .with_context(|| format!("binding {}", args.listen))?;
    log(&format!("forwarding {} -> enclave", args.listen));
    let slots = permits(MAX_FORWARDED);
    loop {
        let (mut client, peer) = l.accept().await?;
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let args = args.clone();
        tokio::spawn(async move {
            let _permit = permit;
            #[cfg(target_os = "linux")]
            {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    tokio_vsock::VsockStream::connect(tokio_vsock::VsockAddr::new(
                        args.enclave_cid,
                        args.enclave_port,
                    )),
                )
                .await
                .unwrap_or_else(|_| Err(std::io::Error::other("timed out")))
                {
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
        IpAddr::V4(v) => {
            !(v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_unspecified()
                || v.is_broadcast()
                || v.octets()[0] == 100 && (v.octets()[1] & 0xc0) == 64)
        }
        IpAddr::V6(v) => {
            !(v.is_loopback()
                || v.is_unspecified()
                || (v.segments()[0] & 0xfe00) == 0xfc00
                || (v.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

async fn handle_tunnel<S: Io>(args: Args, s: S) -> Result<()> {
    let mut r = BufReader::new(s);
    let mut line = String::new();
    // A short, bounded request line, promptly.
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        (&mut r).take(512).read_line(&mut line),
    )
    .await
    .context("tunnel request timed out")??;
    let target = line
        .trim()
        .strip_prefix("CONNECT ")
        .context("expected CONNECT")?
        .to_string();
    let (host, port) = target.rsplit_once(':').context("expected host:port")?;
    let port: u16 = port.parse()?;
    let addrs: Vec<std::net::SocketAddr> =
        tokio::time::timeout(std::time::Duration::from_secs(10), tokio::net::lookup_host((host, port)))
            .await
            .ok()
            .and_then(|r| r.ok())
            .map(|a| a.collect())
            .unwrap_or_default();
    let ok_addr = addrs
        .into_iter()
        .find(|a| (port == 443 && public(a.ip())) || (args.dev && a.ip().is_loopback()));
    let Some(addr) = ok_addr else {
        r.get_mut()
            .write_all(b"ERR destination not allowed\n")
            .await?;
        bail!("refused tunnel to {target}");
    };
    let mut up = match tokio::time::timeout(std::time::Duration::from_secs(10), TcpStream::connect(addr))
        .await
        .unwrap_or_else(|_| Err(std::io::Error::other("connect timed out")))
    {
        Ok(u) => u,
        Err(e) => {
            r.get_mut()
                .write_all(format!("ERR {e}\n").as_bytes())
                .await?;
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
        let slots = permits(MAX_TUNNELS);
        loop {
            let (s, _) = l.accept().await?;
            let Ok(permit) = slots.clone().try_acquire_owned() else {
                continue;
            };
            let a = args.clone();
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = handle_tunnel(a, s).await {
                    log(&format!("tunnel: {e:#}"));
                }
            });
        }
    }
    #[cfg(target_os = "linux")]
    {
        let l = tokio_vsock::VsockListener::bind(tokio_vsock::VsockAddr::new(
            tokio_vsock::VMADDR_CID_ANY,
            args.tunnel_port,
        ))?;
        log(&format!("tunnel on vsock {}", args.tunnel_port));
        let slots = permits(MAX_TUNNELS);
        loop {
            let (s, _) = l.accept().await?;
            let Ok(permit) = slots.clone().try_acquire_owned() else {
                continue;
            };
            let a = args.clone();
            tokio::spawn(async move {
                let _permit = permit;
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
        let l = tokio_vsock::VsockListener::bind(tokio_vsock::VsockAddr::new(
            tokio_vsock::VMADDR_CID_ANY,
            args.config_port,
        ))?;
        log(&format!("config on vsock {}", args.config_port));
        let slots = permits(16);
        loop {
            let (mut s, _) = l.accept().await?;
            let Ok(permit) = slots.clone().try_acquire_owned() else {
                continue;
            };
            let body = body.clone();
            tokio::spawn(async move {
                let _permit = permit;
                use tokio::io::AsyncReadExt;
                let _ = s.write_all(&body).await;
                let _ = AsyncWriteExt::shutdown(&mut s).await;
                // Keep the socket open until the enclave closes it, so it
                // can finish reading.
                let mut sink = [0u8; 64];
                let _ = tokio::time::timeout(std::time::Duration::from_secs(30), s.read(&mut sink))
                    .await;
            });
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

// ------------------------------------------------------------------ sealed file store

/// Sealed files, one directory per session tag: `<dir>/<tag hex>/<id hex>`.
struct Blobs {
    dir: std::path::PathBuf,
    quota: u64,
    used: std::sync::Mutex<u64>,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Total size of the regular files under `p`.
fn dir_size(p: &std::path::Path) -> u64 {
    let Ok(rd) = std::fs::read_dir(p) else { return 0 };
    rd.flatten()
        .map(|e| match e.file_type() {
            Ok(t) if t.is_dir() => dir_size(&e.path()),
            Ok(t) if t.is_file() => e.metadata().map(|m| m.len()).unwrap_or(0),
            _ => 0,
        })
        .sum()
}

/// Remove everything under `p`, returning the bytes actually freed.
fn remove_all_under(p: &std::path::Path) -> u64 {
    let Ok(rd) = std::fs::read_dir(p) else { return 0 };
    let mut freed = 0;
    for e in rd.flatten() {
        let path = e.path();
        match e.file_type() {
            Ok(t) if t.is_dir() => {
                freed += remove_all_under(&path);
                let _ = std::fs::remove_dir(&path);
            }
            _ => {
                let n = e.metadata().map(|m| m.len()).unwrap_or(0);
                if std::fs::remove_file(&path).is_ok() {
                    freed += n;
                }
            }
        }
    }
    freed
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f).await.context("disk worker")
}

impl Blobs {
    /// Open the store, keeping what's there: this daemon may have restarted
    /// under a running enclave whose sessions still need their files.
    async fn open(args: &Args) -> Result<Self> {
        let dir = std::path::PathBuf::from(&args.blob_dir);
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let d = dir.clone();
        let used = blocking(move || dir_size(&d)).await?;
        log(&format!("blob store at {}: {} MiB kept", dir.display(), used >> 20));
        Ok(Self {
            dir,
            quota: args.blob_quota_gib << 30,
            used: std::sync::Mutex::new(used),
        })
    }

    fn path(&self, id: &[u8; 24]) -> std::path::PathBuf {
        self.dir.join(hex(&id[..8])).join(hex(&id[8..]))
    }

    fn add(&self, delta: i64) {
        let mut u = self.used.lock().unwrap_or_else(|p| p.into_inner());
        *u = if delta >= 0 { u.saturating_add(delta as u64) } else { u.saturating_sub(delta.unsigned_abs()) };
    }

    /// Store a blob: reserve its size, write a temporary file and rename it
    /// into place; replacing a blob credits the old one's size. On failure
    /// the reservation is returned.
    async fn put(self: &std::sync::Arc<Self>, id: [u8; 24], data: Vec<u8>) -> Result<(), String> {
        let len = data.len() as u64;
        {
            let mut u = self.used.lock().unwrap_or_else(|p| p.into_inner());
            if *u + len > self.quota {
                return Err("blob store full".into());
            }
            *u += len;
        }
        let (b, path) = (self.clone(), self.path(&id));
        let r = blocking(move || -> std::io::Result<u64> {
            std::fs::create_dir_all(path.parent().unwrap())?;
            let old = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            let tmp = path.with_extension("tmp");
            std::fs::write(&tmp, &data)?;
            std::fs::rename(&tmp, &path).inspect_err(|_| {
                let _ = std::fs::remove_file(&tmp);
            })?;
            Ok(old)
        })
        .await;
        match r {
            Ok(Ok(old)) => {
                b.add(-(old as i64));
                Ok(())
            }
            Ok(Err(e)) => {
                b.add(-(len as i64));
                Err(e.to_string())
            }
            Err(e) => {
                b.add(-(len as i64));
                Err(e.to_string())
            }
        }
    }
}

/// op u8 | id [24] | len u64le | data  ->  status u8 | len u64le | data
///   1 put, 2 get, 3 delete everything with this id's 8-byte session tag,
///   4 reset: a new enclave booted, so everything stored is unreadable now.
async fn handle_blob<S: Io>(b: std::sync::Arc<Blobs>, mut s: S) -> Result<()> {
    use tokio::io::AsyncReadExt;
    let op = s.read_u8().await?;
    let mut id = [0u8; 24];
    s.read_exact(&mut id).await?;
    let len = s.read_u64_le().await?;
    if len > MAX_BLOB_BYTES {
        bail!("blob too large");
    }
    let mut data = vec![0u8; len as usize];
    s.read_exact(&mut data).await?;
    let reply = |status: u8, body: &[u8]| {
        let mut out = vec![status];
        out.extend_from_slice(&(body.len() as u64).to_le_bytes());
        out.extend_from_slice(body);
        out
    };
    let out = match op {
        1 => match b.put(id, data).await {
            Ok(()) => reply(0, b""),
            Err(e) => reply(2, e.as_bytes()),
        },
        2 => match tokio::fs::read(b.path(&id)).await {
            Ok(d) => reply(0, &d),
            Err(_) => reply(1, b""),
        },
        3 => {
            let dir = b.dir.join(hex(&id[..8]));
            let freed = blocking(move || {
                let n = remove_all_under(&dir);
                let _ = std::fs::remove_dir(&dir);
                n
            })
            .await?;
            b.add(-(freed as i64));
            reply(0, b"")
        }
        4 => {
            let dir = b.dir.clone();
            let freed = blocking(move || remove_all_under(&dir)).await?;
            b.add(-(freed as i64));
            log(&format!("blob store: new enclave boot; cleared {} MiB", freed >> 20));
            reply(0, b"")
        }
        _ => reply(2, b"bad op"),
    };
    s.write_all(&out).await?;
    s.flush().await?;
    Ok(())
}

async fn blob_server(args: Args, b: std::sync::Arc<Blobs>) -> Result<()> {
    let slots = permits(MAX_BLOB_REQUESTS);
    let serve = |s: Box<dyn Io>, permit: tokio::sync::OwnedSemaphorePermit| {
        let b = b.clone();
        tokio::spawn(async move {
            let _permit = permit;
            // The enclave gives each exchange two minutes; so does this side.
            match tokio::time::timeout(std::time::Duration::from_secs(150), handle_blob(b, s)).await {
                Ok(Err(e)) => log(&format!("blob: {e:#}")),
                Err(_) => log("blob: request timed out"),
                Ok(Ok(())) => {}
            }
        });
    };
    if args.dev {
        let l = TcpListener::bind(&args.dev_blobs).await?;
        log(&format!("dev blob store on {}", args.dev_blobs));
        loop {
            let (s, _) = l.accept().await?;
            if let Ok(p) = slots.clone().try_acquire_owned() {
                serve(Box::new(s), p);
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        let l = tokio_vsock::VsockListener::bind(tokio_vsock::VsockAddr::new(
            tokio_vsock::VMADDR_CID_ANY,
            5005,
        ))?;
        log("blob store on vsock 5005");
        loop {
            let (s, _) = l.accept().await?;
            if let Ok(p) = slots.clone().try_acquire_owned() {
                serve(Box::new(s), p);
            }
        }
    }
    #[allow(unreachable_code)]
    {
        bail!("vsock requires linux; use --dev")
    }
}

/// Print the enclave's log lines (it has no console in production).
async fn log_server() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let l = tokio_vsock::VsockListener::bind(tokio_vsock::VsockAddr::new(
            tokio_vsock::VMADDR_CID_ANY,
            5004,
        ))?;
        let slots = permits(16);
        loop {
            let (s, _) = l.accept().await?;
            let Ok(permit) = slots.clone().try_acquire_owned() else {
                continue;
            };
            tokio::spawn(async move {
                let _permit = permit;
                let mut lines = BufReader::new(s).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let line: String = line
                        .chars()
                        .filter(|c| !c.is_control())
                        .take(2000)
                        .collect();
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
    let mut s = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        TcpStream::connect("169.254.169.254:80"),
    )
    .await??;
    let mut req = format!("{method} {path} HTTP/1.0\r\nHost: 169.254.169.254\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        (&mut s).take(64 * 1024).read_to_end(&mut buf),
    )
    .await??;
    let text = String::from_utf8_lossy(&buf).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").context("bad IMDS response")?;
    if !head.starts_with("HTTP/1.0 200") && !head.starts_with("HTTP/1.1 200") {
        bail!("IMDS {path}: {}", head.lines().next().unwrap_or(""));
    }
    Ok(body.to_string())
}

async fn role_credentials() -> Result<Vec<u8>> {
    let token = imds(
        "PUT",
        "/latest/api/token",
        &[("X-aws-ec2-metadata-token-ttl-seconds", "60")],
    )
    .await?;
    let h = [("X-aws-ec2-metadata-token", token.trim())];
    let role = imds("GET", "/latest/meta-data/iam/security-credentials/", &h).await?;
    let role = role
        .lines()
        .next()
        .context("no instance role attached")?
        .trim()
        .to_string();
    if role.is_empty()
        || !role
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_+=,.@-".contains(c))
    {
        bail!("invalid role name");
    }
    let v: serde_json::Value = serde_json::from_str(
        &imds(
            "GET",
            &format!("/latest/meta-data/iam/security-credentials/{role}"),
            &h,
        )
        .await?,
    )?;
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
        let l = tokio_vsock::VsockListener::bind(tokio_vsock::VsockAddr::new(
            tokio_vsock::VMADDR_CID_ANY,
            args.credentials_port,
        ))?;
        log(&format!("credentials on vsock {}", args.credentials_port));
        let slots = permits(16);
        loop {
            let (mut s, _) = l.accept().await?;
            let Ok(permit) = slots.clone().try_acquire_owned() else {
                continue;
            };
            tokio::spawn(async move {
                let _permit = permit;
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
