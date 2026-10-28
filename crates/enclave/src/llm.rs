//! Provider adapters. The conversation is kept provider-neutral and rendered
//! to each API's format per call.

use crate::net::{HttpResponse, Net};
use anyhow::{anyhow, bail, Context, Result};
use attest_core::Provider;
use serde_json::{json, Value};
use std::time::Duration;

/// Fixed endpoints. The auditee picks a provider, never a URL: a free-form
/// base URL would let them point the enclave at a server they control.
pub fn endpoint(p: Provider) -> (&'static str, &'static str) {
    match p {
        Provider::Openai => ("api.openai.com", "/v1/chat/completions"),
        Provider::Anthropic => ("api.anthropic.com", "/v1/messages"),
        Provider::Openrouter => ("openrouter.ai", "/api/v1/chat/completions"),
        Provider::Mock => ("(dev mock)", "/v1/chat/completions"),
    }
}

/// Refuse model identifiers that bring provider-side network access with
/// them (web search, browsing, research agents) or let the provider pick
/// the model (aliases, presets, auto-routing).
pub fn vet_model(p: Provider, model: &str) -> anyhow::Result<()> {
    let m = model.to_ascii_lowercase();
    anyhow::ensure!(
        !m.is_empty()
            && m.len() < 200
            && m.chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_./:".contains(c)),
        "invalid model name"
    );
    anyhow::ensure!(
        !m.starts_with('~') && !m.starts_with('@'),
        "model aliases and presets are not allowed; name an exact model"
    );
    let fine_tune = p == Provider::Openai && m.starts_with("ft:");
    anyhow::ensure!(
        !m.contains(':') || fine_tune,
        "model variants (\":online\" and other suffixes) are not allowed; name the base model"
    );
    // OpenRouter's own models (auto, fusion, ...) are routers: they pick
    // other models and some run web search and fetch on the model's behalf.
    anyhow::ensure!(
        !m.starts_with("openrouter/"),
        "OpenRouter router models are not allowed; name an exact model"
    );
    for bad in [
        "search",
        "research",
        "online",
        "sonar",
        "computer-use",
        "browse",
        "router",
        "fusion",
        "agent",
    ] {
        anyhow::ensure!(!m.contains(bad), "models with built-in web or agent access ({bad}) are not allowed: the provider would reach the network on the model's behalf");
    }
    Ok(())
}

/// How OpenRouter may route an approved model: which upstream hosts may
/// serve it (empty: any) and whether only zero-data-retention endpoints may.
/// The parties agree on these out of band; the enclave enforces them on
/// every request and records them in the certificate.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Routing {
    pub zdr: bool,
    pub only: Vec<String>,
}

/// OpenRouter plugins a request can switch off. Account defaults apply to
/// any request that doesn't mention a plugin, and some of these reach the
/// network (web, web-fetch) or swap the model (the routers), so every
/// request turns them all off explicitly. `jev-router` and `alignment`
/// don't accept `enabled: false`; `check_reported_model` catches a swap.
pub const OPENROUTER_PLUGINS_OFF: &[&str] = &[
    "auto-router",
    "auto-beta-router",
    "moderation",
    "web",
    "web-fetch",
    "file-parser",
    "response-healing",
    "context-compression",
    "tool-filter",
    "pareto-router",
    "fusion",
    "switchyard-router",
    "armor",
];

/// Check upstream host names as OpenRouter writes them: a provider slug,
/// optionally with an endpoint suffix ("google-vertex", "amazon-bedrock",
/// "google-vertex/us").
pub fn vet_routing(provider: Provider, only: &[String]) -> anyhow::Result<()> {
    if only.is_empty() {
        return Ok(());
    }
    anyhow::ensure!(
        provider == Provider::Openrouter,
        "openrouter_only applies to the openrouter provider"
    );
    anyhow::ensure!(only.len() <= 8, "at most 8 upstream hosts");
    for h in only {
        anyhow::ensure!(
            !h.is_empty()
                && h.len() <= 64
                && h.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "-/".contains(c))
                && !h.starts_with('/')
                && !h.ends_with('/'),
            "invalid upstream host {h:?} (use OpenRouter slugs like \"google-vertex\")"
        );
    }
    Ok(())
}

/// Add the agreed routing and the plugin switch-offs to an OpenRouter
/// request body, replacing anything the body said about either.
pub fn apply_openrouter(obj: &mut serde_json::Map<String, Value>, r: &Routing) {
    let mut p = serde_json::Map::new();
    if r.zdr {
        p.insert("zdr".into(), json!(true));
        p.insert("data_collection".into(), json!("deny"));
    }
    if !r.only.is_empty() {
        p.insert("only".into(), json!(r.only));
        p.insert("allow_fallbacks".into(), json!(false));
    }
    obj.remove("provider");
    if !p.is_empty() {
        obj.insert("provider".into(), Value::Object(p));
    }
    obj.insert(
        "plugins".into(),
        OPENROUTER_PLUGINS_OFF
            .iter()
            .map(|id| json!({"id": id, "enabled": false}))
            .collect(),
    );
}

/// OpenRouter reports the model that answered. Anything other than the
/// approved one means something rerouted the request (an account-default
/// router plugin, say), so the reply is refused.
pub fn check_reported_model(approved: &str, reported: Option<&str>) -> Result<(), String> {
    match reported {
        Some(m) if m != approved => Err(format!(
            "OpenRouter answered with model {m:?}, not the approved {approved:?}"
        )),
        _ => Ok(()),
    }
}

pub fn is_fine_tuned(p: Provider, model: &str) -> bool {
    match p {
        Provider::Openai | Provider::Mock => model.starts_with("ft:"),
        // OpenRouter does not serve customer fine-tunes; Anthropic has no
        // public fine-tune ids.
        _ => false,
    }
}

#[derive(Clone, Debug)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub args: Value,
}

#[derive(Clone, Debug)]
pub enum Turn {
    User(String),
    Assistant { raw: Value },
    ToolResults(Vec<(String, String)>),
}

pub struct Reply {
    pub text: String,
    pub calls: Vec<ToolCall>,
    pub raw_message: Value,
    pub model: Option<String>,
    pub upstream_provider: Option<String>,
    pub key_owner: Option<String>,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

pub struct Client {
    pub provider: Provider,
    pub model: String,
    api_key: String,
    pub routing: Routing,
    mock: Option<(String, u16)>,
    net: Net,
}

impl Client {
    pub fn new(
        net: Net,
        provider: Provider,
        model: String,
        api_key: String,
        routing: Routing,
        mock: Option<String>,
    ) -> Result<Self> {
        let mock = match (provider, mock) {
            (Provider::Mock, Some(m)) => {
                let (h, p) = m
                    .rsplit_once(':')
                    .ok_or_else(|| anyhow!("mock endpoint must be host:port"))?;
                Some((h.to_string(), p.parse()?))
            }
            (Provider::Mock, None) => bail!("mock provider needs mock_endpoint"),
            _ => None,
        };
        Ok(Self {
            provider,
            model,
            api_key,
            routing,
            mock,
            net,
        })
    }

    pub async fn complete(
        &self,
        system: &str,
        turns: &[Turn],
        tools: &[(&str, &str, Value)],
    ) -> Result<Reply> {
        let body = match self.provider {
            Provider::Anthropic => anthropic_body(&self.model, system, turns, tools),
            _ => openai_body(
                &self.model,
                system,
                turns,
                tools,
                (self.provider == Provider::Openrouter).then_some(&self.routing),
            ),
        };
        let body = pad_json(serde_json::to_vec(&body)?);
        let mut attempt = 0;
        loop {
            attempt += 1;
            let resp = self.send(body.clone()).await;
            let retry = match &resp {
                Err(_) => true,
                Ok(r) => r.status == 429 || r.status >= 500,
            };
            if retry && attempt < 6 {
                tokio::time::sleep(Duration::from_secs(2u64.pow(attempt))).await;
                continue;
            }
            let resp = resp?;
            if resp.status != 200 {
                bail!(
                    "{} returned HTTP {}: {}",
                    self.provider.as_str(),
                    resp.status,
                    String::from_utf8_lossy(&resp.body[..resp.body.len().min(2000)])
                );
            }
            let reply = match self.provider {
                Provider::Anthropic => parse_anthropic(&resp)?,
                _ => parse_openai(&resp)?,
            };
            if self.provider == Provider::Openrouter {
                check_reported_model(&self.model, reply.model.as_deref())
                    .map_err(|e| anyhow!(e))?;
            }
            return Ok(reply);
        }
    }

    async fn send(&self, body: Vec<u8>) -> Result<HttpResponse> {
        let (host, path) = endpoint(self.provider);
        let auth = format!("Bearer {}", self.api_key);
        let timeout = Duration::from_secs(600);
        match self.provider {
            Provider::Anthropic => {
                let h = [
                    ("x-api-key", self.api_key.as_str()),
                    ("anthropic-version", "2023-06-01"),
                ];
                self.net
                    .request(true, host, 443, path, &h, body, timeout)
                    .await
            }
            Provider::Mock => {
                let (mh, mp) = self.mock.as_ref().unwrap();
                self.net
                    .request(
                        false,
                        mh,
                        *mp,
                        path,
                        &[("authorization", &auth)],
                        body,
                        timeout,
                    )
                    .await
            }
            _ => {
                self.net
                    .request(
                        true,
                        host,
                        443,
                        path,
                        &[("authorization", &auth)],
                        body,
                        timeout,
                    )
                    .await
            }
        }
    }
}

/// Pad a JSON body with trailing spaces up to a size bucket. The parent
/// sees each request's size; buckets are at least 64 KiB and grow by 1.25x,
/// so what one tool result or reply adds to the conversation mostly stays
/// inside a bucket.
pub fn pad_json(mut body: Vec<u8>) -> Vec<u8> {
    let mut bucket: usize = 64 << 10;
    while bucket < body.len() {
        bucket = (bucket + bucket / 4).div_ceil(4096) * 4096;
    }
    body.resize(bucket, b' ');
    body
}

// ------------------------------------------------------------------ OpenAI

fn openai_body(
    model: &str,
    system: &str,
    turns: &[Turn],
    tools: &[(&str, &str, Value)],
    openrouter: Option<&Routing>,
) -> Value {
    let mut messages = vec![json!({"role": "system", "content": system})];
    for t in turns {
        match t {
            Turn::User(s) => messages.push(json!({"role": "user", "content": s})),
            Turn::Assistant { raw, .. } => messages.push(raw.clone()),
            Turn::ToolResults(rs) => {
                for (id, content) in rs {
                    messages.push(json!({"role": "tool", "tool_call_id": id, "content": content}));
                }
            }
        }
    }
    let tools: Vec<Value> = tools
        .iter()
        .map(|(n, d, p)| json!({"type": "function", "function": {"name": n, "description": d, "parameters": p}}))
        .collect();
    let mut body = json!({"model": model, "messages": messages, "tools": tools, "max_completion_tokens": 16000});
    if let (Some(r), Some(obj)) = (openrouter, body.as_object_mut()) {
        apply_openrouter(obj, r);
    }
    body
}

fn parse_openai(resp: &HttpResponse) -> Result<Reply> {
    let v: Value = serde_json::from_slice(&resp.body).context("provider response JSON")?;
    let msg = v["choices"][0]["message"].clone();
    if msg.is_null() {
        bail!("provider response has no message");
    }
    let mut calls = Vec::new();
    if let Some(tc) = msg["tool_calls"].as_array() {
        for c in tc {
            let args_s = c["function"]["arguments"].as_str().unwrap_or("{}");
            calls.push(ToolCall {
                id: c["id"].as_str().unwrap_or_default().to_string(),
                name: c["function"]["name"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                args: serde_json::from_str(args_s).unwrap_or(Value::Null),
            });
        }
    }
    // Keep only the fields the API accepts back.
    let mut raw = json!({"role": "assistant", "content": msg["content"].clone()});
    if msg.get("tool_calls").map(|t| !t.is_null()).unwrap_or(false) {
        raw["tool_calls"] = msg["tool_calls"].clone();
    }
    Ok(Reply {
        text: msg["content"].as_str().unwrap_or_default().to_string(),
        calls,
        raw_message: raw,
        model: v["model"].as_str().map(String::from),
        upstream_provider: v["provider"].as_str().map(String::from),
        key_owner: resp.header("openai-organization").map(String::from),
        input_tokens: v["usage"]["prompt_tokens"].as_u64().unwrap_or(0),
        output_tokens: v["usage"]["completion_tokens"].as_u64().unwrap_or(0),
    })
}

// ------------------------------------------------------------------ Anthropic

fn anthropic_body(
    model: &str,
    system: &str,
    turns: &[Turn],
    tools: &[(&str, &str, Value)],
) -> Value {
    // Consecutive user turns (tool results, then a follow-up message) are
    // merged into one user message of content blocks.
    let mut messages: Vec<Value> = Vec::new();
    for t in turns {
        let (role, blocks): (&str, Vec<Value>) = match t {
            Turn::User(s) => ("user", vec![json!({"type": "text", "text": s})]),
            Turn::Assistant { raw, .. } => {
                ("assistant", raw.as_array().cloned().unwrap_or_default())
            }
            Turn::ToolResults(rs) => (
                "user",
                rs.iter()
                    .map(|(id, c)| json!({"type": "tool_result", "tool_use_id": id, "content": c}))
                    .collect(),
            ),
        };
        match messages.last_mut() {
            Some(last) if last["role"] == role => {
                last["content"].as_array_mut().unwrap().extend(blocks);
            }
            _ => messages.push(json!({"role": role, "content": blocks})),
        }
    }
    let tools: Vec<Value> = tools
        .iter()
        .map(|(n, d, p)| json!({"name": n, "description": d, "input_schema": p}))
        .collect();
    json!({"model": model, "system": system, "messages": messages, "tools": tools, "max_tokens": 16000})
}

fn parse_anthropic(resp: &HttpResponse) -> Result<Reply> {
    let v: Value = serde_json::from_slice(&resp.body).context("provider response JSON")?;
    let content = v["content"]
        .as_array()
        .cloned()
        .ok_or_else(|| anyhow!("response has no content"))?;
    let mut text = String::new();
    let mut calls = Vec::new();
    for b in &content {
        match b["type"].as_str() {
            Some("text") => text.push_str(b["text"].as_str().unwrap_or_default()),
            Some("tool_use") => calls.push(ToolCall {
                id: b["id"].as_str().unwrap_or_default().to_string(),
                name: b["name"].as_str().unwrap_or_default().to_string(),
                args: b["input"].clone(),
            }),
            _ => {}
        }
    }
    Ok(Reply {
        text,
        calls,
        raw_message: Value::Array(content),
        model: v["model"].as_str().map(String::from),
        upstream_provider: None,
        key_owner: resp.header("anthropic-organization-id").map(String::from),
        input_tokens: v["usage"]["input_tokens"].as_u64().unwrap_or(0)
            + v["usage"]["cache_read_input_tokens"].as_u64().unwrap_or(0)
            + v["usage"]["cache_creation_input_tokens"]
                .as_u64()
                .unwrap_or(0),
        output_tokens: v["usage"]["output_tokens"].as_u64().unwrap_or(0),
    })
}

/// Keep the conversation under a character budget by eliding the oldest
/// tool outputs first. The model is told what was elided.
pub fn fit_context(turns: &mut [Turn], budget_chars: usize) {
    let size = |ts: &[Turn]| -> usize {
        ts.iter()
            .map(|t| match t {
                Turn::User(s) => s.len(),
                Turn::Assistant { raw, .. } => raw.to_string().len(),
                Turn::ToolResults(rs) => rs.iter().map(|(_, c)| c.len()).sum(),
            })
            .sum()
    };
    let mut total = size(turns);
    if total <= budget_chars {
        return;
    }
    // Never touch the last few turns.
    let keep_from = turns.len().saturating_sub(6);
    for t in turns[..keep_from].iter_mut() {
        if let Turn::ToolResults(rs) = t {
            for (_, c) in rs.iter_mut() {
                if c.len() > 400 {
                    let mut cut = 300;
                    while !c.is_char_boundary(cut) {
                        cut -= 1;
                    }
                    let removed = c.len() - cut;
                    *c = format!("{}\n[... {removed} characters of this older tool output were elided to fit the context window; call the tool again if you need it]", &c[..cut]);
                    total -= removed.min(total);
                }
            }
        }
        if total <= budget_chars {
            return;
        }
    }
}
