//! A minimal S3 client for the sealed file store: PUT, GET, ListObjectsV2
//! and DeleteObjects, SigV4-signed with the instance role's credentials.
//! Everything it stores is ciphertext the enclave sealed; this side never
//! holds a key that could open it.

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub struct Creds {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

/// Where requests go. AWS: virtual-hosted style over HTTPS. A configured
/// endpoint (dev, or an S3-compatible store): path style, http or https.
#[derive(Clone)]
enum Endpoint {
    Aws,
    Custom { https: bool, host: String, port: u16 },
}

pub struct S3 {
    bucket: String,
    region: String,
    endpoint: Endpoint,
    tls: tokio_rustls::TlsConnector,
    /// Cached credentials and when to refresh them.
    creds: tokio::sync::Mutex<Option<(Creds, std::time::Instant)>>,
    fetch: Arc<dyn Fn() -> futures::BoxFuture<Result<(Creds, Duration)>> + Send + Sync>,
}

pub mod futures {
    pub type BoxFuture<T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send>>;
}

pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Largest response body read (a sealed blob, or a list page).
const MAX_BODY: usize = 96 << 20;

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// UTC (YYYYMMDD, YYYYMMDDTHHMMSSZ) from Unix seconds.
fn amz_dates(unix: u64) -> (String, String) {
    let days = (unix / 86_400) as i64;
    let secs = unix % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let date = format!("{y:04}{m:02}{d:02}");
    let full = format!("{date}T{:02}{:02}{:02}Z", secs / 3600, (secs / 60) % 60, secs % 60);
    (date, full)
}

/// RFC 3986 percent-encoding as SigV4 wants it (`/` kept in paths).
fn uri_encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) || (keep_slash && b == b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// SigV4 headers for one request. `headers` are the extra headers to send
/// (all signed); host, x-amz-date, x-amz-content-sha256 and the session
/// token are added here.
#[allow(clippy::too_many_arguments)]
pub fn sign(
    c: &Creds,
    region: &str,
    method: &str,
    host: &str,
    path: &str,
    query: &[(String, String)],
    headers: &[(String, String)],
    body: &[u8],
    unix: u64,
) -> Vec<(String, String)> {
    let (date, amz_date) = amz_dates(unix);
    let payload = hex::encode(Sha256::digest(body));
    let mut h: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    h.push(("host".into(), host.into()));
    h.push(("x-amz-content-sha256".into(), payload.clone()));
    h.push(("x-amz-date".into(), amz_date.clone()));
    if let Some(t) = &c.session_token {
        h.push(("x-amz-security-token".into(), t.clone()));
    }
    h.sort();
    let signed: Vec<&str> = h.iter().map(|(k, _)| k.as_str()).collect();
    let signed = signed.join(";");
    let canonical_headers: String = h.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let mut q: Vec<(String, String)> = query
        .iter()
        .map(|(k, v)| (uri_encode(k, false), uri_encode(v, false)))
        .collect();
    q.sort();
    let canonical_query = q.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&");
    let canonical = format!(
        "{method}\n{}\n{canonical_query}\n{canonical_headers}\n{signed}\n{payload}",
        uri_encode(path, true)
    );
    let scope = format!("{date}/{region}/s3/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical.as_bytes()))
    );
    let k = hmac(format!("AWS4{}", c.secret_access_key).as_bytes(), date.as_bytes());
    let k = hmac(&k, region.as_bytes());
    let k = hmac(&k, b"s3");
    let k = hmac(&k, b"aws4_request");
    let signature = hex::encode(hmac(&k, to_sign.as_bytes()));
    h.retain(|(k, _)| k != "host");
    h.push((
        "authorization".into(),
        format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={signature}",
            c.access_key_id
        ),
    ));
    h
}

/// Text of every `<tag>` element, with XML entities undone.
fn xml_all(xml: &str, tag: &str) -> Vec<String> {
    let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find(&open) {
        let after = &rest[i + open.len()..];
        let Some(j) = after.find(&close) else { break };
        out.push(
            after[..j]
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"")
                .replace("&apos;", "'")
                .replace("&amp;", "&"),
        );
        rest = &after[j + close.len()..];
    }
    out
}

impl S3 {
    /// `endpoint`: None for AWS, or a URL such as http://127.0.0.1:19000.
    pub fn new(
        bucket: &str,
        region: &str,
        endpoint: Option<&str>,
        fetch: Arc<dyn Fn() -> futures::BoxFuture<Result<(Creds, Duration)>> + Send + Sync>,
    ) -> Result<Self> {
        anyhow::ensure!(
            !bucket.is_empty()
                && bucket.len() <= 63
                && bucket.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "bucket names here are lowercase letters, digits and dashes"
        );
        anyhow::ensure!(
            !region.is_empty() && region.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "invalid region"
        );
        let endpoint = match endpoint {
            None => Endpoint::Aws,
            Some(u) => {
                let (https, rest) = if let Some(r) = u.strip_prefix("https://") {
                    (true, r)
                } else if let Some(r) = u.strip_prefix("http://") {
                    (false, r)
                } else {
                    bail!("S3 endpoint must start with http:// or https://");
                };
                let rest = rest.trim_end_matches('/');
                let (host, port) = match rest.rsplit_once(':') {
                    Some((h, p)) => (h.to_string(), p.parse().context("endpoint port")?),
                    None => (rest.to_string(), if https { 443 } else { 80 }),
                };
                Endpoint::Custom { https, host, port }
            }
        };
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            bucket: bucket.into(),
            region: region.into(),
            endpoint,
            tls: tokio_rustls::TlsConnector::from(Arc::new(cfg)),
            creds: tokio::sync::Mutex::new(None),
            fetch,
        })
    }

    async fn creds(&self) -> Result<Creds> {
        let mut g = self.creds.lock().await;
        if let Some((c, until)) = &*g {
            if std::time::Instant::now() < *until {
                return Ok(c.clone());
            }
        }
        let (c, ttl) = (self.fetch)().await.context("instance role credentials")?;
        // Refresh five minutes before they expire.
        let ttl = ttl.saturating_sub(Duration::from_secs(300)).max(Duration::from_secs(30));
        *g = Some((c.clone(), std::time::Instant::now() + ttl));
        Ok(c)
    }

    fn host_and_path(&self, key: &str) -> (String, bool, u16, String) {
        match &self.endpoint {
            Endpoint::Aws => (
                format!("{}.s3.{}.amazonaws.com", self.bucket, self.region),
                true,
                443,
                format!("/{key}"),
            ),
            Endpoint::Custom { https, host, port } => {
                let path = if key.is_empty() { format!("/{}", self.bucket) } else { format!("/{}/{key}", self.bucket) };
                (host.clone(), *https, *port, path)
            }
        }
    }

    /// One request, signed, with bounded retries for network errors,
    /// throttling and 5xx.
    async fn request(
        &self,
        method: &str,
        key: &str,
        query: &[(String, String)],
        headers: &[(String, String)],
        body: Vec<u8>,
        timeout: Duration,
    ) -> Result<Response> {
        let (host, https, port, path) = self.host_and_path(key);
        let host_header = if (https && port == 443) || (!https && port == 80) {
            host.clone()
        } else {
            format!("{host}:{port}")
        };
        let mut delay = Duration::from_millis(200);
        let mut last = anyhow!("no attempt");
        for attempt in 0..5 {
            if attempt > 0 {
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_secs(5));
            }
            let c = self.creds().await?;
            let unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let signed = sign(&c, &self.region, method, &host_header, &path, query, headers, &body, unix);
            let r = tokio::time::timeout(
                timeout,
                self.send(method, &host, https, port, &host_header, &path, query, &signed, body.clone()),
            )
            .await
            .unwrap_or_else(|_| Err(anyhow!("S3 request timed out")));
            match r {
                Ok(resp) if resp.status == 429 || resp.status >= 500 => {
                    last = anyhow!("S3 {method} {key}: HTTP {}", resp.status);
                }
                Ok(resp) => return Ok(resp),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    #[allow(clippy::too_many_arguments)]
    async fn send(
        &self,
        method: &str,
        host: &str,
        https: bool,
        port: u16,
        host_header: &str,
        path: &str,
        query: &[(String, String)],
        headers: &[(String, String)],
        body: Vec<u8>,
    ) -> Result<Response> {
        let tcp = tokio::net::TcpStream::connect((host, port)).await.context("connecting to S3")?;
        let mut uri = uri_encode(path, true);
        if !query.is_empty() {
            uri.push('?');
            uri.push_str(
                &query
                    .iter()
                    .map(|(k, v)| format!("{}={}", uri_encode(k, false), uri_encode(v, false)))
                    .collect::<Vec<_>>()
                    .join("&"),
            );
        }
        let mut req = hyper::Request::builder().method(method).uri(uri).header("host", host_header);
        for (k, v) in headers {
            req = req.header(k.as_str(), v.as_str());
        }
        let req = req.body(Full::new(Bytes::from(body)))?;
        let resp = if https {
            let name = rustls::pki_types::ServerName::try_from(host.to_string())?;
            let tls = self.tls.connect(name, tcp).await.context("TLS to S3")?;
            let (mut sender, conn) =
                hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls)).await?;
            tokio::spawn(conn);
            sender.send_request(req).await?
        } else {
            let (mut sender, conn) =
                hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tcp)).await?;
            tokio::spawn(conn);
            sender.send_request(req).await?
        };
        let status = resp.status().as_u16();
        let body = http_body_util::Limited::new(resp.into_body(), MAX_BODY)
            .collect()
            .await
            .map_err(|e| anyhow!("reading S3 response: {e}"))?
            .to_bytes()
            .to_vec();
        Ok(Response { status, body })
    }

    pub async fn put(&self, key: &str, data: Vec<u8>) -> Result<()> {
        let r = self.request("PUT", key, &[], &[], data, Duration::from_secs(120)).await?;
        if r.status != 200 {
            bail!("S3 PUT {key}: HTTP {} {}", r.status, String::from_utf8_lossy(&r.body[..r.body.len().min(300)]));
        }
        Ok(())
    }

    /// None if there's no such object.
    pub async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let r = self.request("GET", key, &[], &[], Vec::new(), Duration::from_secs(120)).await?;
        match r.status {
            200 => Ok(Some(r.body)),
            404 => Ok(None),
            s => bail!("S3 GET {key}: HTTP {s} {}", String::from_utf8_lossy(&r.body[..r.body.len().min(300)])),
        }
    }

    /// One page of keys under `prefix`, and the token for the next page.
    pub async fn list(&self, prefix: &str, token: Option<&str>) -> Result<(Vec<String>, Option<String>)> {
        let mut q = vec![("list-type".to_string(), "2".to_string()), ("prefix".to_string(), prefix.to_string())];
        if let Some(t) = token {
            q.push(("continuation-token".into(), t.into()));
        }
        let r = self.request("GET", "", &q, &[], Vec::new(), Duration::from_secs(60)).await?;
        if r.status != 200 {
            bail!("S3 list {prefix}: HTTP {}", r.status);
        }
        let xml = String::from_utf8_lossy(&r.body);
        let next = if xml_all(&xml, "IsTruncated").first().map(|s| s == "true").unwrap_or(false) {
            xml_all(&xml, "NextContinuationToken").into_iter().next()
        } else {
            None
        };
        Ok((xml_all(&xml, "Key"), next))
    }

    /// Delete up to 1000 keys in one request.
    pub async fn delete_many(&self, keys: &[String]) -> Result<()> {
        if keys.is_empty() {
            return Ok(());
        }
        let mut body = String::from("<Delete><Quiet>true</Quiet>");
        for k in keys {
            body.push_str(&format!("<Object><Key>{k}</Key></Object>"));
        }
        body.push_str("</Delete>");
        let body = body.into_bytes();
        let checksum = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&body));
        let headers = vec![
            ("content-type".to_string(), "application/xml".to_string()),
            ("x-amz-checksum-sha256".to_string(), checksum),
            ("x-amz-sdk-checksum-algorithm".to_string(), "SHA256".to_string()),
        ];
        let r = self
            .request("POST", "", &[("delete".to_string(), String::new())], &headers, body, Duration::from_secs(60))
            .await?;
        if r.status != 200 {
            bail!("S3 delete: HTTP {} {}", r.status, String::from_utf8_lossy(&r.body[..r.body.len().min(300)]));
        }
        let xml = String::from_utf8_lossy(&r.body);
        if xml.contains("<Error>") {
            bail!("S3 delete: some keys failed: {}", xml_all(&xml, "Code").join(", "));
        }
        Ok(())
    }

    /// Delete every object under `prefix` (skipping keys `keep` accepts).
    /// Returns how many were deleted.
    pub async fn delete_prefix(&self, prefix: &str, keep: impl Fn(&str) -> bool) -> Result<usize> {
        let mut token: Option<String> = None;
        let mut n = 0;
        loop {
            let (keys, next) = self.list(prefix, token.as_deref()).await?;
            let doomed: Vec<String> = keys.into_iter().filter(|k| !keep(k)).collect();
            for chunk in doomed.chunks(1000) {
                self.delete_many(chunk).await?;
                n += chunk.len();
            }
            match next {
                Some(t) => token = Some(t),
                None => return Ok(n),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigv4_s3_get_matches_aws_example() {
        // AWS's documented S3 SigV4 example: GET /test.txt with a Range header.
        // https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
        let c = Creds {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
        };
        // 20130524T000000Z
        let h = sign(
            &c,
            "us-east-1",
            "GET",
            "examplebucket.s3.amazonaws.com",
            "/test.txt",
            &[],
            &[("range".into(), "bytes=0-9".into())],
            b"",
            1_369_353_600,
        );
        let auth = &h.iter().find(|(k, _)| k == "authorization").unwrap().1;
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn sigv4_s3_list_matches_aws_example() {
        // AWS's documented GET Bucket (list) example: ?max-keys=2&prefix=J
        let c = Creds {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
        };
        let h = sign(
            &c,
            "us-east-1",
            "GET",
            "examplebucket.s3.amazonaws.com",
            "/",
            &[("max-keys".into(), "2".into()), ("prefix".into(), "J".into())],
            &[],
            b"",
            1_369_353_600,
        );
        let auth = &h.iter().find(|(k, _)| k == "authorization").unwrap().1;
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
        );
    }

    #[test]
    fn xml_parsing() {
        let x = "<R><IsTruncated>true</IsTruncated><Contents><Key>a/b</Key></Contents><Contents><Key>c&amp;d</Key></Contents><NextContinuationToken>t+1=</NextContinuationToken></R>";
        assert_eq!(xml_all(x, "Key"), vec!["a/b", "c&d"]);
        assert_eq!(xml_all(x, "NextContinuationToken"), vec!["t+1="]);
    }
}
