//! Where model requests go. A `Target` is resolved once, when a model is
//! proposed or approved: the provider, the exact host, which API shape it
//! speaks (Anthropic Messages or OpenAI), the path for each API, and how to
//! authenticate. Besides the model makers' own APIs and OpenRouter, this
//! covers the clouds that serve their models: Amazon Bedrock (Claude and
//! GPT), Google Vertex AI (Claude) and Azure (GPT and Claude).
//!
//! For the clouds, the region, project or resource decides whose account
//! the requests reach, so it's part of the agreement, like the key: the
//! party that supplies the key also supplies those.

use crate::net::Net;
use anyhow::{anyhow, bail, ensure, Context, Result};
use attest_core::Provider;
use serde_json::{json, Value};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Hosts this image may ever send model requests to: exact names, or with
/// `*` standing for exactly one DNS label (a cloud region or resource).
pub const EGRESS: &[&str] = &[
    "api.openai.com",
    "api.anthropic.com",
    "openrouter.ai",
    "bedrock-runtime.*.amazonaws.com",
    "aiplatform.googleapis.com",
    "aiplatform.us.rep.googleapis.com",
    "aiplatform.eu.rep.googleapis.com",
    "oauth2.googleapis.com",
    "*.openai.azure.com",
    "*.services.ai.azure.com",
];

/// The request shape a target speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wire {
    Anthropic,
    Openai,
}

/// A model API endpoint, as a harness asks for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Api {
    Messages,
    Responses,
    Chat,
}

impl Api {
    pub fn from_path(p: &str) -> Option<Api> {
        match p.trim_start_matches("/v1") {
            "/messages" => Some(Api::Messages),
            "/responses" => Some(Api::Responses),
            "/chat/completions" => Some(Api::Chat),
            _ => None,
        }
    }
    fn suffix(self) -> &'static str {
        match self {
            Api::Messages => "messages",
            Api::Responses => "responses",
            Api::Chat => "chat/completions",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Target {
    pub provider: Provider,
    pub host: String,
    /// The shape the built-in agent uses. (OpenRouter speaks both; jailed
    /// harnesses may use either there.)
    pub wire: Wire,
    /// Vertex only: project and location.
    vertex: Option<(String, String)>,
    /// Dev only: plain-HTTP port of a mock server.
    pub mock_port: Option<u16>,
}

fn label(s: &str, what: &str, max: usize) -> Result<String> {
    let s = s.trim().to_ascii_lowercase();
    ensure!(
        !s.is_empty()
            && s.len() <= max
            && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            && !s.starts_with('-')
            && !s.ends_with('-'),
        "invalid {what} {s:?}"
    );
    Ok(s)
}

fn field<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(|x| x.as_str()).map(str::trim).filter(|s| !s.is_empty())
}

impl Target {
    /// Resolve a target from a proposal: `provider`, `model`, and for the
    /// clouds `region` (bedrock), `project` and `location` (vertex),
    /// `resource` and `api` (azure).
    pub fn resolve(provider: Provider, model: &str, v: &Value, mock: Option<&str>) -> Result<Target> {
        let m = model.to_ascii_lowercase();
        let t = |host: String, wire| Target { provider, host, wire, vertex: None, mock_port: None };
        Ok(match provider {
            Provider::Openai => t("api.openai.com".into(), Wire::Openai),
            Provider::Anthropic => t("api.anthropic.com".into(), Wire::Anthropic),
            Provider::Openrouter => t("openrouter.ai".into(), Wire::Openai),
            Provider::Mock => {
                let (h, p) = mock
                    .and_then(|m| m.rsplit_once(':'))
                    .ok_or_else(|| anyhow!("mock endpoint must be host:port"))?;
                Target { mock_port: Some(p.parse()?), ..t(h.to_string(), Wire::Openai) }
            }
            Provider::Bedrock => {
                let region = label(
                    field(v, "region").ok_or_else(|| anyhow!("bedrock needs a region, e.g. \"us-east-1\""))?,
                    "region",
                    30,
                )?;
                // Model ids: [global.|us.|eu.|...]anthropic.claude-... or openai.gpt-...
                let base = m.split_once('.').filter(|(p, _)| p.len() <= 6 && !["anthropic", "openai"].contains(p)).map(|(_, b)| b).unwrap_or(&m);
                let wire = if base.starts_with("anthropic.") {
                    Wire::Anthropic
                } else if base.starts_with("openai.") {
                    Wire::Openai
                } else {
                    bail!("bedrock model ids start with anthropic. or openai. (optionally after a profile such as global. or us.)");
                };
                t(format!("bedrock-runtime.{region}.amazonaws.com"), wire)
            }
            Provider::Vertex => {
                let project = label(
                    field(v, "project").ok_or_else(|| anyhow!("vertex needs a project id"))?,
                    "project id",
                    30,
                )?;
                let location = field(v, "location").unwrap_or("global").to_ascii_lowercase();
                let host = match location.as_str() {
                    "global" => "aiplatform.googleapis.com",
                    "us" => "aiplatform.us.rep.googleapis.com",
                    "eu" => "aiplatform.eu.rep.googleapis.com",
                    _ => bail!("vertex location must be global, us or eu (Anthropic's current models aren't served regionally)"),
                };
                ensure!(m.starts_with("claude-"), "vertex serves Anthropic models here: claude-...");
                Target { vertex: Some((project, location)), ..t(host.into(), Wire::Anthropic) }
            }
            Provider::Azure => {
                let resource = label(
                    field(v, "resource").ok_or_else(|| anyhow!("azure needs the resource name (the NAME in NAME.openai.azure.com)"))?,
                    "resource name",
                    63,
                )?;
                match field(v, "api").unwrap_or("openai") {
                    "openai" => t(format!("{resource}.openai.azure.com"), Wire::Openai),
                    "anthropic" => t(format!("{resource}.services.ai.azure.com"), Wire::Anthropic),
                    other => bail!("azure api must be openai or anthropic, not {other:?}"),
                }
            }
        })
    }

    /// The cloud fields of this target, as a proposal states them.
    pub fn params(&self) -> Value {
        match self.provider {
            Provider::Bedrock => json!({"region": self.host.split('.').nth(1)}),
            Provider::Vertex => {
                let (p, l) = self.vertex.clone().unwrap_or_default();
                json!({"project": p, "location": l})
            }
            Provider::Azure => json!({
                "resource": self.host.split('.').next(),
                "api": if self.wire == Wire::Anthropic { "anthropic" } else { "openai" },
            }),
            _ => json!({}),
        }
    }

    /// Whether the region, project or resource names an account (so it
    /// must come from whoever supplies the key).
    pub fn has_account_params(&self) -> bool {
        matches!(self.provider, Provider::Bedrock | Provider::Vertex | Provider::Azure)
    }

    /// Where requests go, for the certificate and the parties' views.
    pub fn describe(&self) -> String {
        match &self.vertex {
            Some((p, l)) => format!("{}/v1/projects/{p}/locations/{l}", self.host),
            None => self.host.clone(),
        }
    }

    /// The APIs a harness may use here.
    pub fn apis(&self) -> &'static [Api] {
        match (self.provider, self.wire) {
            (Provider::Openrouter, _) => &[Api::Messages, Api::Responses, Api::Chat],
            (_, Wire::Anthropic) => &[Api::Messages],
            (_, Wire::Openai) => &[Api::Responses, Api::Chat],
        }
    }

    /// The upstream path for `api`, or None if this target doesn't serve it.
    pub fn path(&self, api: Api, model: &str, stream: bool) -> Option<String> {
        if !self.apis().contains(&api) {
            return None;
        }
        let s = api.suffix();
        Some(match self.provider {
            Provider::Openrouter => format!("/api/v1/{s}"),
            Provider::Bedrock | Provider::Azure => match self.wire {
                Wire::Anthropic => format!("/anthropic/v1/{s}"),
                Wire::Openai => format!("/openai/v1/{s}"),
            },
            Provider::Vertex => {
                let (p, l) = self.vertex.as_ref()?;
                let verb = if stream { "streamRawPredict" } else { "rawPredict" };
                format!("/v1/projects/{p}/locations/{l}/publishers/anthropic/models/{model}:{verb}")
            }
            _ => format!("/v1/{s}"),
        })
    }

    /// Adjust a vetted request body for this target. Vertex takes the model
    /// from the URL and wants its own anthropic_version in the body.
    pub fn adapt_body(&self, body: &mut serde_json::Map<String, Value>) {
        if self.provider == Provider::Vertex {
            body.remove("model");
            body.insert("anthropic_version".into(), json!("vertex-2023-10-16"));
        }
    }

    /// Whether to send the anthropic-version header (Vertex takes it in the body).
    pub fn wants_version_header(&self) -> bool {
        self.provider != Provider::Vertex
    }

    /// Hosts this target needs on the egress allowlist; each must match `EGRESS`.
    pub fn hosts(&self) -> Vec<String> {
        let mut h = vec![self.host.clone()];
        if self.provider == Provider::Vertex {
            h.push("oauth2.googleapis.com".into());
        }
        h
    }
}

/// Whether `host` matches an `EGRESS` pattern.
pub fn egress_allows(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    EGRESS.iter().any(|p| match p.strip_prefix("*.") {
        Some(rest) => host
            .strip_suffix(rest)
            .and_then(|l| l.strip_suffix('.'))
            .is_some_and(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')),
        None => match p.split_once(".*.") {
            Some((pre, post)) => host
                .strip_prefix(pre)
                .and_then(|r| r.strip_prefix('.'))
                .and_then(|r| r.strip_suffix(post))
                .and_then(|l| l.strip_suffix('.'))
                .is_some_and(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')),
            None => host == *p,
        },
    })
}

/// A target's credentials and how to present them.
pub struct Creds {
    target: Target,
    key: String,
    google: Option<GoogleKey>,
    token: Mutex<Option<(String, Instant)>>,
}

struct GoogleKey {
    email: String,
    key_id: String,
    pkcs8: Vec<u8>,
}

impl Creds {
    pub fn new(target: &Target, key: &str) -> Result<Self> {
        let google = if target.provider == Provider::Vertex {
            Some(parse_google_key(key)?)
        } else {
            None
        };
        Ok(Creds { target: target.clone(), key: key.to_string(), google, token: Mutex::new(None) })
    }

    /// Check a key's form when it's supplied, before any run.
    pub fn check(target: &Target, key: &str) -> Result<()> {
        if target.provider == Provider::Vertex {
            parse_google_key(key)?;
        } else {
            ensure!(key.len() < 1000, "key too long");
        }
        Ok(())
    }

    /// Authentication headers for one request to `api`.
    pub async fn headers(&self, net: &Net, api: Api) -> Result<Vec<(String, String)>> {
        let t = &self.target;
        Ok(match t.provider {
            Provider::Anthropic => vec![("x-api-key".into(), self.key.clone())],
            Provider::Vertex => vec![("authorization".into(), format!("Bearer {}", self.google_token(net).await?))],
            Provider::Azure if t.wire == Wire::Openai => vec![("api-key".into(), self.key.clone())],
            Provider::Azure => vec![("x-api-key".into(), self.key.clone())],
            Provider::Bedrock if api == Api::Messages => vec![("x-api-key".into(), self.key.clone())],
            _ => vec![("authorization".into(), format!("Bearer {}", self.key))],
        })
    }

    /// A Google access token from the service-account key: a signed JWT
    /// exchanged at oauth2.googleapis.com (always that host, whatever the
    /// key file names). Cached until shortly before it expires.
    async fn google_token(&self, net: &Net) -> Result<String> {
        if let Some((tok, until)) = self.token.lock().unwrap().clone() {
            if Instant::now() < until {
                return Ok(tok);
            }
        }
        let g = self.google.as_ref().ok_or_else(|| anyhow!("no service-account key"))?;
        let now = attest_core::now_ms() / 1000;
        let b64 = |b: &[u8]| {
            use base64::Engine;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
        };
        let header = json!({"alg": "RS256", "typ": "JWT", "kid": g.key_id});
        let claims = json!({
            "iss": g.email,
            "scope": "https://www.googleapis.com/auth/cloud-platform",
            "aud": "https://oauth2.googleapis.com/token",
            "iat": now,
            "exp": now + 3600,
        });
        let signing_input = format!("{}.{}", b64(header.to_string().as_bytes()), b64(claims.to_string().as_bytes()));
        let kp = ring::signature::RsaKeyPair::from_pkcs8(&g.pkcs8).map_err(|e| anyhow!("service-account key: {e}"))?;
        let mut sig = vec![0u8; kp.public().modulus_len()];
        kp.sign(&ring::signature::RSA_PKCS1_SHA256, &ring::rand::SystemRandom::new(), signing_input.as_bytes(), &mut sig)
            .map_err(|_| anyhow!("signing the token request failed"))?;
        let jwt = format!("{signing_input}.{}", b64(&sig));
        let form = format!("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={jwt}");
        let resp = net
            .request(
                true,
                "oauth2.googleapis.com",
                443,
                "/token",
                &[("content-type", "application/x-www-form-urlencoded")],
                form.into_bytes(),
                Duration::from_secs(30),
            )
            .await
            .context("getting a Google access token")?;
        let v: Value = serde_json::from_slice(&resp.body).unwrap_or(Value::Null);
        let tok = v["access_token"]
            .as_str()
            .ok_or_else(|| anyhow!("Google refused the service-account key (HTTP {}): {}", resp.status, v["error_description"].as_str().or(v["error"].as_str()).unwrap_or("")))?
            .to_string();
        // Google says an hour; clamp whatever it says, so a bogus value can't
        // overflow the deadline.
        let ttl = v["expires_in"]
            .as_u64()
            .unwrap_or(3600)
            .min(3600)
            .saturating_sub(300)
            .max(60);
        *self.token.lock().unwrap() = Some((tok.clone(), Instant::now() + Duration::from_secs(ttl)));
        Ok(tok)
    }
}

fn parse_google_key(key: &str) -> Result<GoogleKey> {
    ensure!(key.len() < 8000, "service-account key too long");
    let v: Value = serde_json::from_str(key)
        .map_err(|_| anyhow!("for vertex, api_key is the service-account key file (JSON)"))?;
    ensure!(v["type"] == "service_account", "the key file must be a service-account key");
    let email = v["client_email"].as_str().ok_or_else(|| anyhow!("key file has no client_email"))?;
    let pem = v["private_key"].as_str().ok_or_else(|| anyhow!("key file has no private_key"))?;
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect::<Vec<_>>().join("");
    let pkcs8 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.decode(b64.trim()).map_err(|_| anyhow!("private_key is not PEM"))?
    };
    ring::signature::RsaKeyPair::from_pkcs8(&pkcs8).map_err(|e| anyhow!("private_key is not an RSA PKCS#8 key: {e}"))?;
    Ok(GoogleKey {
        email: email.to_string(),
        key_id: v["private_key_id"].as_str().unwrap_or("").to_string(),
        pkcs8,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(p: Provider, m: &str, v: Value) -> Result<Target> {
        Target::resolve(p, m, &v, None)
    }

    #[test]
    fn resolving() {
        let b = r(Provider::Bedrock, "global.anthropic.claude-opus-5-5", json!({"region": "us-east-1"})).unwrap();
        assert_eq!(b.host, "bedrock-runtime.us-east-1.amazonaws.com");
        assert_eq!(b.wire, Wire::Anthropic);
        assert_eq!(b.path(Api::Messages, "x", true).unwrap(), "/anthropic/v1/messages");
        assert!(b.path(Api::Responses, "x", false).is_none());
        let g = r(Provider::Bedrock, "us.openai.gpt-6-sol", json!({"region": "us-west-2"})).unwrap();
        assert_eq!(g.wire, Wire::Openai);
        assert_eq!(g.path(Api::Responses, "x", false).unwrap(), "/openai/v1/responses");
        assert!(r(Provider::Bedrock, "meta.llama", json!({"region": "us-east-1"})).is_err());
        assert!(r(Provider::Bedrock, "anthropic.claude-opus-5-5", json!({"region": "evil.com/x"})).is_err());
        assert!(r(Provider::Bedrock, "anthropic.claude-opus-5-5", json!({})).is_err());

        let v = r(Provider::Vertex, "claude-opus-5-5", json!({"project": "my-proj-1", "location": "us"})).unwrap();
        assert_eq!(v.host, "aiplatform.us.rep.googleapis.com");
        assert_eq!(
            v.path(Api::Messages, "claude-opus-5-5", true).unwrap(),
            "/v1/projects/my-proj-1/locations/us/publishers/anthropic/models/claude-opus-5-5:streamRawPredict"
        );
        assert!(r(Provider::Vertex, "claude-opus-5-5", json!({"project": "p/../x"})).is_err());
        assert!(r(Provider::Vertex, "gemini-3", json!({"project": "my-proj-1"})).is_err());
        let mut body = serde_json::Map::new();
        body.insert("model".into(), json!("claude-opus-5-5"));
        v.adapt_body(&mut body);
        assert!(body.get("model").is_none() && body["anthropic_version"] == "vertex-2023-10-16");

        let a = r(Provider::Azure, "my-gpt6", json!({"resource": "contoso"})).unwrap();
        assert_eq!(a.host, "contoso.openai.azure.com");
        assert_eq!(a.path(Api::Chat, "x", false).unwrap(), "/openai/v1/chat/completions");
        let c = r(Provider::Azure, "claude-opus-5-5", json!({"resource": "contoso", "api": "anthropic"})).unwrap();
        assert_eq!(c.host, "contoso.services.ai.azure.com");
        assert_eq!(c.path(Api::Messages, "x", false).unwrap(), "/anthropic/v1/messages");
        assert!(r(Provider::Azure, "x", json!({"resource": "a.b"})).is_err());

        for t in [&b, &g, &v, &a, &c] {
            for h in t.hosts() {
                assert!(egress_allows(&h), "{h}");
            }
        }
    }

    #[test]
    fn egress_patterns() {
        assert!(egress_allows("api.openai.com"));
        assert!(egress_allows("bedrock-runtime.eu-west-2.amazonaws.com"));
        assert!(!egress_allows("bedrock-runtime.evil.com.amazonaws.com"));
        assert!(!egress_allows("bedrock-runtime..amazonaws.com"));
        assert!(!egress_allows("s3.us-east-1.amazonaws.com"));
        assert!(egress_allows("contoso.openai.azure.com"));
        assert!(!egress_allows("a.contoso.openai.azure.com"));
        assert!(!egress_allows("openai.azure.com"));
        assert!(!egress_allows("evil.com"));
    }

    #[test]
    fn google_key_signs() {
        // A throwaway 2048-bit key, generated for this test only.
        let pem = include_str!("../tests/fixtures/test-rsa-key.pem");
        let key = json!({"type": "service_account", "client_email": "x@p.iam.gserviceaccount.com", "private_key": pem, "private_key_id": "k1"}).to_string();
        let t = r(Provider::Vertex, "claude-opus-5-5", json!({"project": "my-proj-1"})).unwrap();
        assert!(Creds::new(&t, &key).is_ok());
        assert!(Creds::new(&t, "not json").is_err());
    }
}
