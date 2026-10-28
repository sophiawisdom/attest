//! Outbound HTTPS from the enclave. The enclave has no network; it asks the
//! untrusted parent for a raw TCP tunnel (`CONNECT host:port`), then runs TLS
//! itself, verifying the provider's certificate against the Mozilla roots
//! compiled into the image. The parent sees only ciphertext.

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub type Stream = Box<dyn Io>;

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub const TUNNEL_VSOCK_PORT: u32 = 5001;

#[derive(Clone)]
pub struct Net {
    dev: bool,
    dev_tunnel: String,
    tls: Arc<rustls::ClientConfig>,
    /// The only hosts this enclave may connect to (outside dev mode). Set
    /// once at boot: model providers, the ACME CA, SES, and itself.
    allowed: Arc<std::sync::RwLock<std::collections::BTreeSet<String>>>,
}

pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

impl Net {
    pub fn new(dev: bool, dev_tunnel: String) -> Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            dev,
            dev_tunnel,
            tls: Arc::new(cfg),
            allowed: Arc::default(),
        })
    }

    pub fn allow(&self, host: &str) {
        self.allowed
            .write()
            .unwrap()
            .insert(host.to_ascii_lowercase());
    }

    pub fn allowed_hosts(&self) -> Vec<String> {
        self.allowed.read().unwrap().iter().cloned().collect()
    }

    async fn dial_parent(&self) -> Result<Stream> {
        if self.dev {
            let s = tokio::net::TcpStream::connect(&self.dev_tunnel)
                .await
                .with_context(|| format!("connecting to dev host tunnel at {}", self.dev_tunnel))?;
            return Ok(Box::new(s));
        }
        #[cfg(target_os = "linux")]
        {
            let s = vsock_connect(TUNNEL_VSOCK_PORT)
                .await
                .context("connecting to parent tunnel")?;
            Ok(Box::new(s))
        }
        #[cfg(not(target_os = "linux"))]
        bail!("vsock requires linux; run with --dev")
    }

    async fn tunnel(&self, host: &str, port: u16) -> Result<Stream> {
        if !self.dev
            && (port != 443
                || !(self
                    .allowed
                    .read()
                    .unwrap()
                    .contains(&host.to_ascii_lowercase())
                    || crate::targets::egress_allows(host)))
        {
            bail!("connection to {host}:{port} refused: not on this enclave's egress allowlist");
        }
        let mut s = self.dial_parent().await?;
        s.write_all(format!("CONNECT {host}:{port}\n").as_bytes())
            .await?;
        // Read the one-line reply byte by byte so nothing after it is consumed.
        let mut line = Vec::new();
        loop {
            let b = s.read_u8().await.context("parent closed tunnel")?;
            if b == b'\n' {
                break;
            }
            line.push(b);
            if line.len() > 512 {
                bail!("parent tunnel reply too long");
            }
        }
        let line = String::from_utf8_lossy(&line);
        if line.trim() != "OK" {
            bail!("parent refused tunnel to {host}:{port}: {line}");
        }
        Ok(s)
    }

    /// TLS handshake with `host` without trusting its certificate, returning
    /// the sha256 of its SubjectPublicKeyInfo.
    pub async fn peer_spki_sha256(&self, host: &str, port: u16) -> Result<String> {
        let raw = tokio::time::timeout(Duration::from_secs(15), self.tunnel(host, port))
            .await
            .map_err(|_| anyhow!("timeout"))??;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let capture = Arc::new(Capture {
            provider: provider.clone(),
            cert: std::sync::Mutex::new(None),
        });
        let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(capture.clone())
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let name = rustls::pki_types::ServerName::try_from(host.to_string())?;
        tokio::time::timeout(
            Duration::from_secs(15),
            tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, raw),
        )
        .await
        .map_err(|_| anyhow!("TLS timeout"))??;
        let cert = capture
            .cert
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| anyhow!("no certificate"))?;
        attest_core::spki_sha256_of_cert(&cert)
    }

    /// JSON POST on a fresh connection.
    pub async fn request(
        &self,
        https: bool,
        host: &str,
        port: u16,
        path: &str,
        headers: &[(&str, &str)],
        body: Vec<u8>,
        timeout: Duration,
    ) -> Result<HttpResponse> {
        let mut h: Vec<(&str, &str)> = vec![("content-type", "application/json")];
        h.extend_from_slice(headers);
        self.request_full("POST", https, host, port, path, &h, body, timeout)
            .await
    }

    /// Any HTTP/1.1 request on a fresh connection.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_full(
        &self,
        method: &str,
        https: bool,
        host: &str,
        port: u16,
        path: &str,
        headers: &[(&str, &str)],
        body: Vec<u8>,
        timeout: Duration,
    ) -> Result<HttpResponse> {
        tokio::time::timeout(
            timeout,
            self.request_inner(method, https, true, host, port, path, headers, body),
        )
        .await
        .map_err(|_| anyhow!("request to {host} timed out"))?
    }

    /// A JSON request to another attest enclave (handoff.rs). Its TLS
    /// certificate isn't checked: both ends rely on Nitro attestations
    /// carried in the messages, not on the connection.
    #[allow(clippy::too_many_arguments)]
    pub async fn request_peer(
        &self,
        method: &str,
        https: bool,
        host: &str,
        port: u16,
        path: &str,
        body: Vec<u8>,
        timeout: Duration,
    ) -> Result<HttpResponse> {
        let h = [("content-type", "application/json")];
        tokio::time::timeout(
            timeout,
            self.request_inner(method, https, false, host, port, path, &h, body),
        )
        .await
        .map_err(|_| anyhow!("request to {host} timed out"))?
    }

    #[allow(clippy::too_many_arguments)]
    async fn request_inner(
        &self,
        method: &str,
        https: bool,
        verify: bool,
        host: &str,
        port: u16,
        path: &str,
        headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> Result<HttpResponse> {
        let raw = self.tunnel(host, port).await?;
        let io: Stream = if https {
            let name = rustls::pki_types::ServerName::try_from(host.to_string())?;
            let cfg = if verify {
                self.tls.clone()
            } else {
                let provider = Arc::new(rustls::crypto::ring::default_provider());
                let mut cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
                    .with_safe_default_protocol_versions()?
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(Capture {
                        provider,
                        cert: std::sync::Mutex::new(None),
                    }))
                    .with_no_client_auth();
                cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
                Arc::new(cfg)
            };
            let tls = tokio_rustls::TlsConnector::from(cfg)
                .connect(name, raw)
                .await
                .with_context(|| format!("TLS to {host}"))?;
            Box::new(tls)
        } else {
            if !self.dev {
                bail!("plaintext HTTP is only allowed in dev mode");
            }
            raw
        };
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let host_header = if (https && port == 443) || (!https && port == 80) {
            host.to_string()
        } else {
            format!("{host}:{port}")
        };
        let mut req = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header("host", host_header);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let resp = sender
            .send_request(req.body(Full::new(Bytes::from(body)))?)
            .await?;
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.to_string(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect();
        let body = http_body_util::Limited::new(resp.into_body(), 64 << 20)
            .collect()
            .await
            .map_err(|e| anyhow!("reading response: {e}"))?
            .to_bytes()
            .to_vec();
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

/// Accepts any certificate and records it (used only to recognise ourselves).
#[derive(Debug)]
struct Capture {
    provider: Arc<rustls::crypto::CryptoProvider>,
    cert: std::sync::Mutex<Option<Vec<u8>>>,
}

impl rustls::client::danger::ServerCertVerifier for Capture {
    fn verify_server_cert(
        &self,
        end: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        *self.cert.lock().unwrap() = Some(end.to_vec());
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
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
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
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

/// Connect to the parent over vsock. The socket is created close-on-exec
/// and nonblocking in one call (tokio-vsock 0.7 sets close-on-exec with
/// F_SETFL, which ignores it), so a jail executor started at any moment
/// can't inherit it and write straight to the parent.
#[cfg(target_os = "linux")]
pub async fn vsock_connect(port: u32) -> std::io::Result<tokio_vsock::VsockStream> {
    use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
    use tokio::io::unix::AsyncFd;
    let fd = unsafe {
        libc::socket(
            libc::AF_VSOCK,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let addr = vsock_addr(libc::VMADDR_CID_HOST, port);
    let r = unsafe {
        libc::connect(
            std::os::fd::AsRawFd::as_raw_fd(&fd),
            &addr as *const libc::sockaddr_vm as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if r < 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(e);
        }
    }
    // Safety: `fd` is an open socket this function owns.
    let afd = unsafe { AsyncFd::register(fd) }?;
    loop {
        let mut guard = afd.writable().await?;
        let mut err: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let r = unsafe {
            libc::getsockopt(
                std::os::fd::AsRawFd::as_raw_fd(afd.get_ref()),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut err as *mut libc::c_int as *mut libc::c_void,
                &mut len,
            )
        };
        if r < 0 {
            return Err(std::io::Error::last_os_error());
        }
        match err {
            0 => break,
            libc::EINPROGRESS | libc::EAGAIN => guard.clear_ready(),
            e => return Err(std::io::Error::from_raw_os_error(e)),
        }
    }
    let raw = afd.into_inner().into_raw_fd();
    tokio_vsock::VsockStream::new(unsafe { vsock::VsockStream::from_raw_fd(raw) })
}

#[cfg(target_os = "linux")]
fn vsock_addr(cid: u32, port: u32) -> libc::sockaddr_vm {
    let mut a: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    a.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    a.svm_cid = cid;
    a.svm_port = port;
    a
}

/// A vsock listener whose accepted sockets are close-on-exec from the
/// start (accept4), unlike the vsock crate's, which uses plain accept.
#[cfg(target_os = "linux")]
pub struct VsockAcceptor {
    fd: tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>,
}

#[cfg(target_os = "linux")]
impl VsockAcceptor {
    pub fn bind(port: u32) -> std::io::Result<Self> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        let fd = unsafe {
            libc::socket(
                libc::AF_VSOCK,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let addr = vsock_addr(libc::VMADDR_CID_ANY, port);
        let ok = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &addr as *const libc::sockaddr_vm as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            ) == 0
                && libc::listen(fd.as_raw_fd(), 1024) == 0
        };
        if !ok {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            // Safety: `fd` is an open socket we own.
            fd: unsafe { tokio::io::unix::AsyncFd::register(fd) }?,
        })
    }

    pub async fn accept(&self) -> std::io::Result<tokio_vsock::VsockStream> {
        use std::os::fd::{AsRawFd, FromRawFd};
        loop {
            let mut guard = self.fd.readable().await?;
            let r = unsafe {
                libc::accept4(
                    self.fd.get_ref().as_raw_fd(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                )
            };
            if r >= 0 {
                return tokio_vsock::VsockStream::new(unsafe { vsock::VsockStream::from_raw_fd(r) });
            }
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::WouldBlock {
                guard.clear_ready();
                continue;
            }
            return Err(e);
        }
    }
}
