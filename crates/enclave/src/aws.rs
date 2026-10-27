//! Minimal AWS client for SES, signed inside the enclave. Credentials are
//! the instance role's, relayed by the untrusted parent (it could withhold
//! them, but TLS to AWS ends here, so it cannot read or change messages).

use crate::net::Net;
#[allow(unused_imports)]
use anyhow::{anyhow, bail, ensure, Context, Result};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::time::Duration;

pub const CREDENTIALS_VSOCK_PORT: u32 = 5003;
const MAX_CREDENTIALS: usize = 16 * 1024;

#[derive(Deserialize, Clone)]
pub struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
}

impl Credentials {
    fn validate(&self) -> Result<()> {
        let ok = |s: &str, max| !s.is_empty() && s.len() <= max && s.bytes().all(|b| b.is_ascii_graphic());
        ensure!(ok(&self.access_key_id, 128) && ok(&self.secret_access_key, 256) && ok(&self.session_token, 8192), "invalid AWS credentials");
        Ok(())
    }
}

/// Instance role credentials from the parent's bridge.
pub async fn credentials(dev: bool) -> Result<Credentials> {
    if dev {
        bail!("no AWS credentials in dev mode");
    }
    #[cfg(target_os = "linux")]
    {
        use tokio::io::AsyncReadExt;
        let addr = tokio_vsock::VsockAddr::new(tokio_vsock::VMADDR_CID_HOST, CREDENTIALS_VSOCK_PORT);
        let stream = tokio::time::timeout(Duration::from_secs(10), tokio_vsock::VsockStream::connect(addr))
            .await
            .map_err(|_| anyhow!("timeout reaching the credential bridge"))??;
        let mut data = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), stream.take((MAX_CREDENTIALS + 1) as u64).read_to_end(&mut data))
            .await
            .map_err(|_| anyhow!("timeout reading credentials"))??;
        ensure!(data.len() <= MAX_CREDENTIALS, "credential response too large");
        let c: Credentials = serde_json::from_slice(&data).map_err(|_| anyhow!("invalid credential response"))?;
        c.validate()?;
        Ok(c)
    }
    #[cfg(not(target_os = "linux"))]
    bail!("the credential bridge requires linux")
}

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

/// SigV4 headers for a form-encoded POST to `/` (AWS query APIs).
pub fn sign_query_post(c: &Credentials, region: &str, service: &str, host: &str, unix: u64, body: &[u8]) -> Vec<(String, String)> {
    let (date, amz_date) = amz_dates(unix);
    let signed = "content-type;host;x-amz-date;x-amz-security-token";
    let content_type = "application/x-www-form-urlencoded; charset=utf-8";
    let canonical_headers = format!("content-type:{content_type}\nhost:{host}\nx-amz-date:{amz_date}\nx-amz-security-token:{}\n", c.session_token);
    let canonical = format!("POST\n/\n\n{canonical_headers}\n{signed}\n{}", hex::encode(Sha256::digest(body)));
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}", hex::encode(Sha256::digest(canonical.as_bytes())));
    let k = hmac(format!("AWS4{}", c.secret_access_key).as_bytes(), date.as_bytes());
    let k = hmac(&k, region.as_bytes());
    let k = hmac(&k, service.as_bytes());
    let k = hmac(&k, b"aws4_request");
    let signature = hex::encode(hmac(&k, to_sign.as_bytes()));
    vec![
        ("content-type".into(), content_type.into()),
        ("x-amz-date".into(), amz_date),
        ("x-amz-security-token".into(), c.session_token.clone()),
        ("authorization".into(), format!("AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={signature}", c.access_key_id)),
    ]
}

fn form(params: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new()).extend_pairs(params).finish()
}

/// One SES (v1 query API) call; returns the XML body.
async fn ses(net: &Net, dev: bool, region: &str, params: &[(&str, &str)]) -> Result<String> {
    let c = credentials(dev).await?;
    let host = format!("email.{region}.amazonaws.com");
    let mut all = vec![("Version", "2010-12-01")];
    all.extend_from_slice(params);
    let body = form(&all).into_bytes();
    let unix = attest_core::now_ms() / 1000;
    let headers = sign_query_post(&c, region, "ses", &host, unix, &body);
    let refs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let r = net.request_full("POST", true, &host, 443, "/", &refs, body, Duration::from_secs(20)).await?;
    let text = String::from_utf8_lossy(&r.body).into_owned();
    if r.status != 200 {
        let code = xml_text(&text, "Code").unwrap_or_default();
        let msg = xml_text(&text, "Message").unwrap_or_default();
        bail!("SES {}: HTTP {} {code} {msg}", params[0].1, r.status);
    }
    Ok(text)
}

fn xml_text(xml: &str, tag: &str) -> Option<String> {
    let start = xml.find(&format!("<{tag}>"))? + tag.len() + 2;
    let end = start + xml[start..].find(&format!("</{tag}>"))?;
    Some(xml[start..end].to_string())
}

/// "Success", "Pending", "Failed", "TemporaryFailure", "NotStarted", or None if unknown to SES.
pub async fn verification_status(net: &Net, dev: bool, region: &str, email: &str) -> Result<Option<String>> {
    let xml = ses(net, dev, region, &[("Action", "GetIdentityVerificationAttributes"), ("Identities.member.1", email)]).await?;
    Ok(xml_text(&xml, "VerificationStatus"))
}

/// Ask SES to send its one-time confirmation email to `email`.
pub async fn request_verification(net: &Net, dev: bool, region: &str, email: &str) -> Result<()> {
    ses(net, dev, region, &[("Action", "VerifyEmailIdentity"), ("EmailAddress", email)]).await.map(|_| ())
}

pub async fn send_email(net: &Net, dev: bool, region: &str, from: &str, to: &str, subject: &str, text: &str) -> Result<()> {
    ses(
        net,
        dev,
        region,
        &[
            ("Action", "SendEmail"),
            ("Source", from),
            ("Destination.ToAddresses.member.1", to),
            ("Message.Subject.Data", subject),
            ("Message.Subject.Charset", "UTF-8"),
            ("Message.Body.Text.Data", text),
            ("Message.Body.Text.Charset", "UTF-8"),
        ],
    )
    .await
    .context("sending email")
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigv4_matches_botocore_reference() {
        // Vector from timelock-proxy, generated with AWS CLI 2.24.21's botocore SigV4Auth.
        let c = Credentials {
            access_key_id: "ASIATESTEXAMPLE".into(),
            secret_access_key: "test-secret-not-a-real-key".into(),
            session_token: "test-session-token".into(),
        };
        let h = sign_query_post(
            &c,
            "us-west-2",
            "ec2",
            "ec2.us-west-2.amazonaws.com",
            1_788_912_000,
            b"Action=DescribeInstances&InstanceId.1=i-1234567890abcdef0&Version=2016-11-15",
        );
        let auth = &h.iter().find(|(k, _)| k == "authorization").unwrap().1;
        assert_eq!(auth, "AWS4-HMAC-SHA256 Credential=ASIATESTEXAMPLE/20260909/us-west-2/ec2/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token, Signature=c6ba9f6464678a4d3152bc70c28dceae7d4c02b255ec05ecc2423c48a78f8723");
    }

    #[test]
    fn dates() {
        assert_eq!(amz_dates(0), ("19700101".into(), "19700101T000000Z".into()));
        assert_eq!(amz_dates(1_793_112_837).1, "20261027T145357Z");
        assert_eq!(amz_dates(951_782_400).0, "20000229");
    }

    #[test]
    fn xml() {
        let x = "<a><VerificationStatus>Success</VerificationStatus></a>";
        assert_eq!(xml_text(x, "VerificationStatus").as_deref(), Some("Success"));
        assert_eq!(xml_text(x, "Nope"), None);
    }
}
