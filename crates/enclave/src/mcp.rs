//! A client for remote MCP servers (the Streamable HTTP transport). The
//! enclave lists a server's tools when the auditee connects it; the auditee
//! picks which ones the agent may call, and the enclave refuses the rest.

use crate::net::Net;
use anyhow::{anyhow, bail, ensure, Context, Result};
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;

const PROTOCOL: &str = "2025-06-18";
const TIMEOUT: Duration = Duration::from_secs(60);
const MAX_BODY: usize = 8 << 20;
pub const MAX_TOOLS: usize = 80;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Tool {
    pub name: String,
    pub description: String,
    pub schema: Value,
    /// The server's own hint that the tool only reads (unverified).
    pub read_only: Option<bool>,
}

/// Where the server is and how to authenticate to it.
#[derive(Serialize, Deserialize, Clone)]
pub struct Server {
    pub https: bool,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub headers: Vec<(String, String)>,
}

/// A live MCP session (not persisted: a new one starts per run).
#[derive(Default)]
pub struct Live {
    session: Option<String>,
    next_id: u64,
    ready: bool,
}

impl Server {
    /// One JSON-RPC message; the reply to it, if it has an id.
    async fn rpc(&self, net: &Net, live: &mut Live, method: &str, params: Value, notify: bool) -> Result<(u16, Option<Value>)> {
        let id = live.next_id;
        live.next_id += 1;
        let msg = if notify {
            json!({"jsonrpc": "2.0", "method": method, "params": params})
        } else {
            json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
        };
        let mut h: Vec<(&str, &str)> = vec![
            ("content-type", "application/json"),
            ("accept", "application/json, text/event-stream"),
            ("user-agent", "attest-enclave"),
            ("mcp-protocol-version", PROTOCOL),
        ];
        for (k, v) in &self.headers {
            h.push((k, v));
        }
        let sid = live.session.clone();
        if let Some(s) = &sid {
            h.push(("mcp-session-id", s));
        }
        let resp = net
            .request_stream("POST", self.https, &self.host, self.port, &self.path, &h, serde_json::to_vec(&msg)?, TIMEOUT)
            .await?;
        let status = resp.status().as_u16();
        if let Some(s) = resp.headers().get("mcp-session-id").and_then(|v| v.to_str().ok()) {
            live.session = Some(s.to_string());
        }
        let sse = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|c| c.starts_with("text/event-stream"));
        if notify || status == 202 {
            return Ok((status, None));
        }
        let mut body = resp.into_body();
        let mut buf: Vec<u8> = Vec::new();
        let found = tokio::time::timeout(TIMEOUT, async {
            loop {
                if sse {
                    // Events are separated by a blank line; each has data: lines.
                    while let Some(end) = find_event_end(&buf) {
                        let event: Vec<u8> = buf.drain(..end).collect();
                        let data: String = String::from_utf8_lossy(&event)
                            .lines()
                            .filter_map(|l| l.strip_prefix("data:"))
                            .map(|l| l.strip_prefix(' ').unwrap_or(l))
                            .collect::<Vec<_>>()
                            .join("\n");
                        if let Ok(v) = serde_json::from_str::<Value>(&data) {
                            if v["id"] == json!(id) && (v.get("result").is_some() || v.get("error").is_some()) {
                                return Ok(Some(v));
                            }
                        }
                    }
                }
                match body.frame().await {
                    Some(f) => {
                        if let Ok(d) = f?.into_data() {
                            buf.extend_from_slice(&d);
                            ensure!(buf.len() <= MAX_BODY, "the MCP server's reply is too large");
                        }
                    }
                    None => break,
                }
            }
            if sse {
                return Ok(None);
            }
            Ok::<_, anyhow::Error>(serde_json::from_slice::<Value>(&buf).ok())
        })
        .await
        .map_err(|_| anyhow!("the MCP server timed out"))??;
        if !(200..300).contains(&status) {
            let text: String = String::from_utf8_lossy(&buf).chars().take(300).collect();
            bail!("the MCP server answered HTTP {status}{}", if text.trim().is_empty() { String::new() } else { format!(": {}", text.trim()) });
        }
        Ok((status, found))
    }

    async fn call(&self, net: &Net, live: &mut Live, method: &str, params: Value) -> Result<Value> {
        let (_, v) = self.rpc(net, live, method, params, false).await?;
        let v = v.context("the MCP server sent no reply")?;
        if let Some(e) = v.get("error") {
            bail!("the MCP server returned an error: {}", e["message"].as_str().unwrap_or("unknown"));
        }
        Ok(v["result"].clone())
    }

    async fn initialize(&self, net: &Net, live: &mut Live) -> Result<Value> {
        *live = Live { next_id: 1, ..Default::default() };
        let r = self
            .call(net, live, "initialize", json!({
                "protocolVersion": PROTOCOL,
                "capabilities": {},
                "clientInfo": {"name": "attest-enclave", "version": env!("CARGO_PKG_VERSION")}
            }))
            .await?;
        self.rpc(net, live, "notifications/initialized", json!({}), true).await?;
        live.ready = true;
        Ok(r)
    }

    /// Connect, and list the server's name and tools.
    pub async fn discover(&self, net: &Net) -> Result<(String, Vec<Tool>)> {
        let mut live = Live::default();
        let init = self.initialize(net, &mut live).await.map_err(|e| {
            anyhow!("{e:#}. The server must speak MCP's Streamable HTTP transport and accept a token in a header (servers that need a sign-in can't be connected)")
        })?;
        let info = &init["serverInfo"];
        let server = format!("{} {}", info["name"].as_str().unwrap_or("unnamed"), info["version"].as_str().unwrap_or("")).trim().to_string();
        let mut tools = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..10 {
            let params = match &cursor {
                Some(c) => json!({"cursor": c}),
                None => json!({}),
            };
            let r = self.call(net, &mut live, "tools/list", params).await?;
            for t in r["tools"].as_array().cloned().unwrap_or_default() {
                let Some(name) = t["name"].as_str() else { continue };
                if tools.len() >= MAX_TOOLS {
                    break;
                }
                let mut schema = t["inputSchema"].clone();
                if !schema.is_object() || serde_json::to_vec(&schema).map(|b| b.len()).unwrap_or(0) > 16_000 {
                    schema = json!({"type": "object"});
                }
                tools.push(Tool {
                    name: name.chars().take(128).collect(),
                    description: t["description"].as_str().unwrap_or("").chars().take(1500).collect(),
                    schema,
                    read_only: t["annotations"]["readOnlyHint"].as_bool(),
                });
            }
            cursor = r["nextCursor"].as_str().map(String::from);
            if cursor.is_none() {
                break;
            }
        }
        Ok((server, tools))
    }

    /// Call one tool; its result as text for the model.
    pub async fn call_tool(&self, net: &Net, live: &mut Live, tool: &str, args: Value) -> Result<String> {
        if !live.ready {
            self.initialize(net, live).await?;
        }
        let params = json!({"name": tool, "arguments": if args.is_object() { args.clone() } else { json!({}) }});
        let r = match self.call(net, live, "tools/call", params.clone()).await {
            // The server forgot the session: start a new one, once.
            Err(e) if format!("{e}").contains("HTTP 404") && live.session.is_some() => {
                self.initialize(net, live).await?;
                self.call(net, live, "tools/call", params).await?
            }
            r => r?,
        };
        let mut out = String::new();
        if r["isError"] == json!(true) {
            out.push_str("[the tool reported an error]\n");
        }
        for c in r["content"].as_array().cloned().unwrap_or_default() {
            match c["type"].as_str() {
                Some("text") => out.push_str(c["text"].as_str().unwrap_or("")),
                Some("resource") => out.push_str(c["resource"]["text"].as_str().unwrap_or("[a binary resource]")),
                Some("resource_link") => out.push_str(&format!("[resource {}]", c["uri"].as_str().unwrap_or("?"))),
                Some(t) => out.push_str(&format!("[{t} content omitted]")),
                None => {}
            }
            out.push('\n');
        }
        if out.trim().is_empty() {
            if let Some(s) = r.get("structuredContent") {
                out = s.to_string();
            }
        }
        Ok(out)
    }
}

fn find_event_end(buf: &[u8]) -> Option<usize> {
    let a = buf.windows(2).position(|w| w == b"\n\n").map(|i| i + 2);
    let b = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4);
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, y) => x.or(y),
    }
}

/// A tool's name as the agent sees it: `connection__tool`, in the
/// characters every model API accepts.
pub fn agent_name(connection: &str, tool: &str) -> String {
    let t: String = tool.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' }).collect();
    format!("{connection}__{t}").chars().take(64).collect()
}
