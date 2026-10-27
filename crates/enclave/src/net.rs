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
}

pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

impl Net {
    pub fn new(dev: bool, dev_tunnel: String) -> Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self { dev, dev_tunnel, tls: Arc::new(cfg) })
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
            let addr = tokio_vsock::VsockAddr::new(tokio_vsock::VMADDR_CID_HOST, TUNNEL_VSOCK_PORT);
            let s = tokio_vsock::VsockStream::connect(addr).await.context("connecting to parent tunnel")?;
            Ok(Box::new(s))
        }
        #[cfg(not(target_os = "linux"))]
        bail!("vsock requires linux; run with --dev")
    }

    async fn tunnel(&self, host: &str, port: u16) -> Result<Stream> {
        let mut s = self.dial_parent().await?;
        s.write_all(format!("CONNECT {host}:{port}\n").as_bytes()).await?;
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

    /// One HTTP/1.1 request on a fresh connection.
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
        tokio::time::timeout(timeout, self.request_inner(https, host, port, path, headers, body))
            .await
            .map_err(|_| anyhow!("request to {host} timed out"))?
    }

    async fn request_inner(
        &self,
        https: bool,
        host: &str,
        port: u16,
        path: &str,
        headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> Result<HttpResponse> {
        let raw = self.tunnel(host, port).await?;
        let io: Stream = if https {
            let name = rustls::pki_types::ServerName::try_from(host.to_string())?;
            let tls = tokio_rustls::TlsConnector::from(self.tls.clone())
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
        let mut req = hyper::Request::post(path).header("host", host).header("content-type", "application/json");
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let resp = sender.send_request(req.body(Full::new(Bytes::from(body)))?).await?;
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned()))
            .collect();
        let body = http_body_util::Limited::new(resp.into_body(), 64 << 20)
            .collect()
            .await
            .map_err(|e| anyhow!("reading response: {e}"))?
            .to_bytes()
            .to_vec();
        Ok(HttpResponse { status, headers, body })
    }
}
