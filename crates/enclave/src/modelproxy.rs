#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]
//! Per-run model proxy for jailed agent harnesses.
//!
//! The harness is configured with `http://127.0.0.1:PORT` as its model API
//! base URL and a random per-run token as its "API key". The proxy checks
//! the token, swaps in the real key, and forwards only the provider's model
//! endpoints, over the enclave's own TLS, to the fixed provider host. Every
//! exchange is recorded for the auditee's transcript.

use crate::net::Net;
use anyhow::Result;
use attest_core::Provider;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Default, Clone)]
pub struct Usage {
    pub calls: u32,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub models: std::collections::BTreeSet<String>,
    pub key_owner: Option<String>,
    pub upstream: std::collections::BTreeSet<String>,
}

pub struct ModelProxy {
    pub port: u16,
    pub token: String,
    pub usage: Arc<Mutex<Usage>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for ModelProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Upstream {
    net: Net,
    provider: Provider,
    model: String,
    api_key: String,
    token: String,
    usage: Arc<Mutex<Usage>>,
    record: Arc<dyn Fn(Value) + Send + Sync>,
}

/// What a jailed harness may ask the provider for. Fail closed: unknown
/// fields and any tool the provider would run itself (web search/fetch,
/// remote MCP servers, code execution, file search) are refused, because
/// those make the provider contact arbitrary URLs, which could carry data
/// out. Also pins the approved model, forces `store: false`, and pads the
/// body to 16 KiB steps so its size says little to the parent.
pub fn vet_request(provider: Provider, path: &str, approved_model: &str, body: &[u8]) -> Result<Vec<u8>, String> {
    let mut v: Value = serde_json::from_slice(body).map_err(|_| "request body is not JSON".to_string())?;
    let obj = v.as_object_mut().ok_or("request body is not a JSON object")?;
    let endpoint = path.rsplit('/').next().unwrap_or("");
    let allowed: &[&str] = match (provider, endpoint) {
        (Provider::Anthropic, _) => &[
            "model", "messages", "system", "tools", "tool_choice", "max_tokens", "stream", "temperature", "top_p",
            "top_k", "thinking", "stop_sequences",
        ],
        (_, "responses") => &[
            "model", "input", "instructions", "tools", "tool_choice", "parallel_tool_calls", "reasoning", "store",
            "stream", "include", "prompt_cache_key", "text", "max_output_tokens", "temperature", "top_p", "truncation",
            "service_tier",
        ],
        _ => &[
            "model", "messages", "tools", "tool_choice", "parallel_tool_calls", "stream", "stream_options", "max_tokens",
            "max_completion_tokens", "temperature", "top_p", "reasoning", "reasoning_effort", "response_format", "stop",
            "seed", "usage",
        ],
    };
    if let Some(bad) = obj.keys().find(|k| !allowed.contains(&k.as_str())) {
        return Err(format!("request field {bad:?} is not allowed through the attest proxy"));
    }
    if obj.get("model").and_then(|m| m.as_str()) != Some(approved_model) {
        return Err(format!("only the approved model {approved_model:?} may be used"));
    }
    if let Some(tools) = obj.get("tools") {
        let tools = tools.as_array().ok_or("tools must be an array")?;
        for t in tools {
            let ty = t.get("type").and_then(|x| x.as_str()).unwrap_or("");
            let ok = match provider {
                // Client tools have no type or "custom"; bash/text_editor
                // tools are executed by the client, inside the jail.
                Provider::Anthropic => ty.is_empty() || ty == "custom" || ty.starts_with("bash_") || ty.starts_with("text_editor_"),
                // Function tools run in the harness; local_shell too.
                _ => ty == "function" || ty == "custom" || ty == "local_shell",
            };
            if !ok {
                return Err(format!("tool type {ty:?} is not allowed: the provider would run it outside the enclave"));
            }
        }
    }
    if endpoint == "responses" {
        obj.insert("store".into(), Value::Bool(false));
    }
    let mut out = serde_json::to_vec(&v).map_err(|e| e.to_string())?;
    let target = out.len().div_ceil(16 << 10) * (16 << 10);
    out.resize(target, b' ');
    Ok(out)
}

/// Map a harness request path to the provider path, or refuse it.
fn upstream_path(provider: Provider, path: &str) -> Option<String> {
    let p = path.trim_start_matches("/v1");
    let allowed = match provider {
        Provider::Anthropic => p == "/messages",
        _ => p == "/responses" || p == "/chat/completions",
    };
    if !allowed {
        return None;
    }
    Some(match provider {
        Provider::Openrouter => format!("/api/v1{p}"),
        _ => format!("/v1{p}"),
    })
}

impl ModelProxy {
    /// Listen on a Unix socket at `socket_path`; the jail bridges one
    /// loopback port in its own empty network namespace to it.
    pub async fn start(net: Net, provider: Provider, model: String, api_key: String, socket_path: &str, record: Arc<dyn Fn(Value) + Send + Sync>) -> Result<Self> {
        let _ = std::fs::remove_file(socket_path);
        let l = tokio::net::UnixListener::bind(socket_path)?;
        let port = 0;
        let mut t = [0u8; 24];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut t);
        let token = hex::encode(t);
        let usage = Arc::new(Mutex::new(Usage::default()));
        let up = Arc::new(Upstream { net, provider, model, api_key, token: token.clone(), usage: usage.clone(), record });
        let task = tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                let up = up.clone();
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |req| {
                        let up = up.clone();
                        async move { Ok::<_, std::convert::Infallible>(handle(up, req).await) }
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(s), svc).await;
                });
            }
        });
        Ok(Self { port, token, usage, task })
    }
}

fn reply(status: StatusCode, msg: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(json!({"error": {"message": msg}}).to_string())))
        .unwrap()
}

async fn handle(up: Arc<Upstream>, req: Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
    let presented = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .or_else(|| req.headers().get("x-api-key").and_then(|v| v.to_str().ok()))
        .unwrap_or("");
    if presented != up.token {
        return reply(StatusCode::UNAUTHORIZED, "wrong proxy token");
    }
    if req.method() != hyper::Method::POST {
        return reply(StatusCode::METHOD_NOT_ALLOWED, "only POST to the model endpoint is forwarded");
    }
    let Some(path) = upstream_path(up.provider, req.uri().path()) else {
        return reply(StatusCode::NOT_FOUND, "only the model endpoint is forwarded");
    };
    // Forward only headers a model API needs.
    let keep = ["content-type", "accept", "openai-beta", "anthropic-version", "anthropic-beta"];
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .filter(|(k, _)| keep.contains(&k.as_str()))
        .map(|(k, v)| (k.to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned()))
        .collect();
    let raw = match http_body_util::Limited::new(req.into_body(), 32 << 20).collect().await {
        Ok(b) => b.to_bytes().to_vec(),
        Err(_) => return reply(StatusCode::PAYLOAD_TOO_LARGE, "request too large"),
    };
    let body = match vet_request(up.provider, &path, &up.model, &raw) {
        Ok(b) => b,
        Err(why) => {
            (up.record)(json!({"type": "error", "content": format!("proxy refused a model request: {why}")}));
            return reply(StatusCode::FORBIDDEN, &why);
        }
    };
    let mut h: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let auth = format!("Bearer {}", up.api_key);
    match up.provider {
        Provider::Anthropic => {
            h.push(("x-api-key", &up.api_key));
            if !h.iter().any(|(k, _)| *k == "anthropic-version") {
                h.push(("anthropic-version", "2023-06-01"));
            }
        }
        _ => h.push(("authorization", &auth)),
    }
    let host = crate::llm::endpoint(up.provider).0;
    let req_summary = summarize_request(&raw);
    let resp = match up.net.request_full("POST", true, host, 443, &path, &h, body, Duration::from_secs(600)).await {
        Ok(r) => r,
        Err(e) => {
            (up.record)(json!({"type": "error", "content": format!("model request failed: {e:#}")}));
            return reply(StatusCode::BAD_GATEWAY, "upstream request failed");
        }
    };
    let text = String::from_utf8_lossy(&resp.body).into_owned();
    {
        let mut u = up.usage.lock().unwrap();
        u.calls += 1;
        let (i, o, m, prov) = usage_of(&text);
        u.input_tokens += i;
        u.output_tokens += o;
        if let Some(m) = m {
            u.models.insert(m);
        }
        if let Some(p) = prov {
            u.upstream.insert(p);
        }
        if u.key_owner.is_none() {
            u.key_owner = resp.header("openai-organization").or(resp.header("anthropic-organization-id")).map(String::from);
        }
    }
    (up.record)(json!({
        "type": "model_exchange",
        "status": resp.status,
        "request": req_summary,
        "response": truncate(&text, 40_000),
    }));
    let ctype = resp.header("content-type").unwrap_or("application/json").to_string();
    Response::builder()
        .status(resp.status)
        .header("content-type", ctype)
        .body(Full::new(Bytes::from(resp.body)))
        .unwrap()
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… [{} more bytes]", &s[..end], s.len() - end)
}

/// The newest input item(s) of a request: what the harness just sent
/// (usually tool output), without repeating the whole history each time.
fn summarize_request(body: &[u8]) -> Value {
    let Ok(v) = serde_json::from_slice::<Value>(body) else { return json!({"bytes": body.len()}) };
    let items = v.get("input").or(v.get("messages")).and_then(|x| x.as_array());
    let last: Vec<Value> = items.map(|a| a.iter().rev().take(3).rev().cloned().collect()).unwrap_or_default();
    let last = serde_json::to_string(&last).unwrap_or_default();
    json!({"model": v.get("model"), "items": items.map(|a| a.len()), "latest": truncate(&last, 20_000), "bytes": body.len()})
}

/// Pull usage, model and provider out of a JSON or SSE response body.
fn usage_of(text: &str) -> (u64, u64, Option<String>, Option<String>) {
    let (mut i, mut o, mut model, mut prov) = (0, 0, None, None);
    let mut take = |v: &Value| {
        let r = v.get("response").unwrap_or(v);
        if let Some(u) = r.get("usage") {
            let gi = |k: &str| u.get(k).and_then(|x| x.as_u64()).unwrap_or(0);
            let ni = gi("input_tokens") + gi("prompt_tokens") + gi("cache_read_input_tokens");
            let no = gi("output_tokens") + gi("completion_tokens");
            if ni + no > 0 {
                i = ni;
                o = no;
            }
        }
        if let Some(m) = r.get("model").and_then(|x| x.as_str()) {
            model = Some(m.to_string());
        }
        if let Some(p) = r.get("provider").and_then(|x| x.as_str()) {
            prov = Some(p.to_string());
        }
    };
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        take(&v);
    } else {
        for line in text.lines() {
            if let Some(d) = line.strip_prefix("data: ") {
                if let Ok(v) = serde_json::from_str::<Value>(d) {
                    take(&v);
                }
            }
        }
    }
    (i, o, model, prov)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert_eq!(upstream_path(Provider::Openai, "/v1/responses").as_deref(), Some("/v1/responses"));
        assert_eq!(upstream_path(Provider::Openrouter, "/v1/chat/completions").as_deref(), Some("/api/v1/chat/completions"));
        assert_eq!(upstream_path(Provider::Anthropic, "/v1/messages").as_deref(), Some("/v1/messages"));
        assert!(upstream_path(Provider::Openai, "/v1/files").is_none());
        assert!(upstream_path(Provider::Anthropic, "/v1/responses").is_none());
    }

    #[test]
    fn vetting() {
        let ok = br#"{"model":"m","input":[],"tools":[{"type":"function","name":"shell"}],"stream":true}"#;
        let out = vet_request(Provider::Openai, "/v1/responses", "m", ok).unwrap();
        assert_eq!(out.len() % (16 << 10), 0);
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["store"], false);
        // Provider-run tools, MCP servers, other models and unknown fields are refused.
        for bad in [
            &br#"{"model":"m","input":[],"tools":[{"type":"web_search"}]}"#[..],
            br#"{"model":"m","input":[],"tools":[{"type":"mcp","server_url":"https://x"}]}"#,
            br#"{"model":"other","input":[]}"#,
            br#"{"model":"m","input":[],"background":true}"#,
            br#"{"model":"m","input":[],"previous_response_id":"r"}"#,
        ] {
            assert!(vet_request(Provider::Openai, "/v1/responses", "m", bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
        assert!(vet_request(Provider::Openrouter, "/api/v1/chat/completions", "m", br#"{"model":"m","messages":[],"plugins":[{"id":"web"}]}"#).is_err());
        assert!(vet_request(Provider::Anthropic, "/v1/messages", "m", br#"{"model":"m","messages":[],"mcp_servers":[]}"#).is_err());
        assert!(vet_request(Provider::Anthropic, "/v1/messages", "m", br#"{"model":"m","messages":[],"tools":[{"type":"web_fetch_20250910","name":"web_fetch"}]}"#).is_err());
        assert!(vet_request(Provider::Anthropic, "/v1/messages", "m", br#"{"model":"m","messages":[],"tools":[{"name":"read","input_schema":{}}]}"#).is_ok());
    }

    #[test]
    fn usage_from_sse() {
        let sse = "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"model\":\"gpt-x\",\"usage\":{\"input_tokens\":10,\"output_tokens\":3}}}\n\n";
        assert_eq!(usage_of(sse), (10, 3, Some("gpt-x".into()), None));
    }

}
