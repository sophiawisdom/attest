//! Obtain a CA-issued certificate for the enclave's own TLS key via ACME
//! (TLS-ALPN-01), adapted from timelock-proxy. This only makes browsers
//! happy: trust comes from the attestation document, which binds the same
//! key whichever certificate is presented.

use crate::net::Net;
use crate::tls::ServerIdentity;
use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use instant_acme::{
    Account, AuthorizationStatus, BodyWrapper, BytesResponse, ChallengeType, HttpClient,
    Identifier, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

/// Let's Encrypt certificates last 90 days. A fresh key per boot means a
/// new certificate per boot anyway.
const RENEW_AFTER: Duration = Duration::from_secs(60 * 24 * 3600);
/// IP-address certificates are short-lived (about six days).
const RENEW_IP_AFTER: Duration = Duration::from_secs(3 * 24 * 3600);

struct NetHttp {
    net: Net,
}

impl HttpClient for NetHttp {
    fn request(
        &self,
        req: http::Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>> {
        let net = self.net.clone();
        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let err = |m: String| instant_acme::Error::Other(m.into());
            let host = parts
                .uri
                .host()
                .ok_or_else(|| err("acme url has no host".into()))?
                .to_string();
            if parts.uri.scheme_str() != Some("https") {
                return Err(err("acme url must be https".into()));
            }
            let pq = parts
                .uri
                .path_and_query()
                .map(|p| p.as_str())
                .unwrap_or("/")
                .to_string();
            let body = http_body_util::BodyExt::collect(body)
                .await
                .map(|c| c.to_bytes().to_vec())
                .unwrap_or_default();
            let headers: Vec<(String, String)> = parts
                .headers
                .iter()
                .map(|(k, v)| {
                    (
                        k.to_string(),
                        String::from_utf8_lossy(v.as_bytes()).into_owned(),
                    )
                })
                .collect();
            let refs: Vec<(&str, &str)> = headers
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            let resp = net
                .request_full(
                    parts.method.as_str(),
                    true,
                    &host,
                    443,
                    &pq,
                    &refs,
                    body,
                    Duration::from_secs(60),
                )
                .await
                .map_err(|e| err(format!("acme http: {e:#}")))?;
            let mut b = http::Response::builder().status(resp.status);
            for (k, v) in &resp.headers {
                b = b.header(k, v);
            }
            let (rparts, ()) = b
                .body(())
                .map_err(|e| err(format!("acme response: {e}")))?
                .into_parts();
            Ok(BytesResponse {
                parts: rparts,
                body: Box::new(Bytes::from(resp.body)),
            })
        })
    }
}

/// Wait until `name` resolves to this enclave: connect to it through the
/// parent and check the TLS key we get back is our own. Requesting a
/// certificate before DNS points here would only burn ACME rate limits.
async fn wait_for_dns(net: &Net, tls: &ServerIdentity, name: &str) {
    let mut logged = false;
    loop {
        match net.peer_spki_sha256(name, 443).await {
            Ok(spki) if spki == tls.spki_sha256 => return,
            Ok(_) => {
                if !logged {
                    crate::log(&format!(
                        "acme: {name} reaches a different server; waiting for DNS to point here"
                    ));
                }
            }
            Err(e) => {
                if !logged {
                    crate::log(&format!(
                        "acme: cannot reach {name} yet ({e:#}); waiting for DNS"
                    ));
                }
            }
        }
        logged = true;
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

pub async fn run(net: Net, tls: Arc<ServerIdentity>, name: String, directory: String) {
    wait_for_dns(&net, &tls, &name).await;
    crate::log(&format!(
        "acme: {name} points at this enclave; requesting a certificate"
    ));
    let mut backoff = Duration::from_secs(60);
    let mut account: Option<Account> = None;
    loop {
        match obtain(&net, &tls, &name, &directory, &mut account).await {
            Ok(()) => {
                backoff = Duration::from_secs(60);
                // Renew when a third of the certificate's lifetime is left,
                // from its actual expiry; the fixed intervals are a fallback.
                let ip = name.parse::<std::net::IpAddr>().is_ok();
                let fallback = if ip { RENEW_IP_AFTER } else { RENEW_AFTER };
                let wait = match tls.current().not_after {
                    Some(exp) => {
                        let left = (exp - (attest_core::now_ms() / 1000) as i64).max(0) as u64;
                        Duration::from_secs(left * 2 / 3).max(Duration::from_secs(3600))
                    }
                    None => fallback,
                };
                crate::log(&format!(
                    "acme: certificate installed for {name}; renewing in {} h",
                    wait.as_secs() / 3600
                ));
                tokio::time::sleep(wait).await;
            }
            Err(e) => {
                tls.clear_challenge();
                crate::log(&format!("acme: {e:#}; retrying in {backoff:?}"));
                tokio::time::sleep(backoff).await;
                // Capped at an hour: a six-day certificate must not run out
                // between attempts.
                backoff = (backoff * 2).min(Duration::from_secs(3600));
            }
        }
    }
}

async fn obtain(
    net: &Net,
    tls: &ServerIdentity,
    name: &str,
    directory: &str,
    account: &mut Option<Account>,
) -> Result<()> {
    // One ACME account per boot, kept across retries so failing validations
    // do not also burn new-account rate limits.
    if account.is_none() {
        let (acct, _creds) = Account::builder_with_http(Box::new(NetHttp { net: net.clone() }))
            .create(
                &NewAccount {
                    contact: &[],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                directory.to_string(),
                None,
            )
            .await
            .context("creating ACME account")?;
        *account = Some(acct);
    }
    let account = account.as_ref().expect("set above");
    let ip = name.parse::<std::net::IpAddr>().ok();
    let idents = [match ip {
        Some(ip) => Identifier::Ip(ip),
        None => Identifier::Dns(name.to_string()),
    }];
    let mut new_order = NewOrder::new(&idents);
    if ip.is_some() {
        new_order = new_order.profile("shortlived");
    }
    let mut order = account.new_order(&new_order).await.context("new order")?;
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result.context("authorization")?;
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            other => bail!("authorization status {other:?}"),
        }
        let mut challenge = authz
            .challenge(ChallengeType::TlsAlpn01)
            .ok_or_else(|| anyhow!("no tls-alpn-01 challenge offered"))?;
        let digest = challenge.key_authorization().digest();
        tls.set_challenge(name, digest.as_ref())?;
        challenge.set_ready().await.context("set_ready")?;
    }
    let status = order
        .poll_ready(&RetryPolicy::default())
        .await
        .context("polling order")?;
    tls.clear_challenge();
    if status != OrderStatus::Ready {
        bail!("order status {status:?}");
    }
    let csr = tls.csr_der(&[name.to_string()])?;
    order.finalize_csr(&csr).await.context("finalize")?;
    let chain = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .context("polling certificate")?;
    tls.install_chain_pem(&chain)?;
    Ok(())
}
