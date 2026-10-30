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

pub async fn run(net: Net, tls: Arc<ServerIdentity>, name: String, extra: Option<String>, directory: String) {
    wait_for_dns(&net, &tls, &name).await;
    crate::log(&format!(
        "acme: {name} points at this enclave; requesting a certificate"
    ));
    let mut backoff = Duration::from_secs(60);
    let mut account: Option<Account> = None;
    // Plus a random one-off name under the domain (a wildcard DNS record
    // points those here): each boot's certificate then covers a new set of
    // names, so restarts don't run into Let's Encrypt's limit of five per
    // week for the same set. Without the wildcard, the domain alone.
    let mut names = vec![name.clone()];
    if name.parse::<std::net::IpAddr>().is_err() {
        let label = format!("b{}.{name}", &hex::encode(ring_random8())[..10]);
        net.allow(&label); // for this self-check only
        if net.peer_spki_sha256(&label, 443).await.is_ok_and(|s| s == tls.spki_sha256) {
            names.push(label);
        } else {
            crate::log(&format!("acme: no wildcard DNS under {name}; asking for {name} alone"));
        }
    }
    loop {
        match obtain(&net, &tls, &names, &directory, &mut account).await {
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
            Err(e) if !names.iter().any(|n| n.parse::<std::net::IpAddr>().is_ok()) && extra.is_some() && format!("{e:#}").contains("rateLimited") => {
                tls.clear_challenge();
                let ip = extra.clone().unwrap();
                crate::log(&format!("acme: {name} alone is rate-limited; asking for {name} and {ip} together"));
                names.push(ip);
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
    names: &[String],
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
    let idents: Vec<Identifier> = names
        .iter()
        .map(|n| match n.parse::<std::net::IpAddr>() {
            Ok(ip) => Identifier::Ip(ip),
            Err(_) => Identifier::Dns(n.to_string()),
        })
        .collect();
    let mut new_order = NewOrder::new(&idents);
    if idents.iter().any(|i| matches!(i, Identifier::Ip(_))) {
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
        let name = match challenge.identifier().identifier {
            Identifier::Ip(ip) => ip.to_string(),
            Identifier::Dns(d) => d.clone(),
            _ => bail!("unexpected identifier type"),
        };
        tls.set_challenge(&name, digest.as_ref())?;
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
    let csr = tls.csr_der(names)?;
    order.finalize_csr(&csr).await.context("finalize")?;
    let chain = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .context("polling certificate")?;
    tls.install_chain_pem(&chain)?;
    Ok(())
}

fn ring_random8() -> [u8; 8] {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 8];
    ring::rand::SystemRandom::new().fill(&mut b).expect("system randomness");
    b
}
