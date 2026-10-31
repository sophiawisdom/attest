//! Services the auditee connects for the agent: Slack, Gmail, Plaid,
//! GitHub's API, any HTTPS API, a mailbox over IMAP (imap.rs) or a remote
//! MCP server (mcp.rs). The enclave keeps each connection's
//! credentials and makes every request itself, over TLS it verifies, adding
//! the credentials on the way out; the model only names the connection.
//! When connecting, the enclave asks the service who the credentials belong
//! to, and that answer goes in every certificate.

use crate::net::Net;
use anyhow::{anyhow, bail, ensure, Context, Result};
use attest_core::{now_ms, ConnectionRecord};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// What the agent gets back from one request, at most.
const MAX_RESPONSE_CHARS: usize = 40_000;
const TIMEOUT: Duration = Duration::from_secs(30);
pub const KINDS: &[&str] = &["slack", "gmail", "plaid", "github_api", "http", "imap", "mcp"];
const METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"];

/// A connection: its public record and the credentials only the enclave
/// sees (kept in the session's sealed state, like model API keys).
#[derive(Serialize, Deserialize, Clone)]
pub struct Connection {
    pub rec: ConnectionRecord,
    secret: Secret,
    /// MCP: the tools the auditee allowed, with their schemas.
    #[serde(default)]
    mcp_tools: Vec<crate::mcp::Tool>,
    /// MCP: the name the server gave itself (unverified).
    #[serde(default)]
    mcp_server: String,
    #[serde(skip)]
    live: LiveSlot,
    /// Set when the auditee removes the connection. Shared with the copies
    /// runs hold, which check it before every request.
    #[serde(skip)]
    revoked: Arc<AtomicBool>,
}

/// What the agent gets when it uses a connection the auditee removed.
pub const REVOKED: &str = "error: this connection was removed by the auditee";

/// An MCP session lasts one run; copies start without one.
#[derive(Default)]
struct LiveSlot(crate::mcp::Live);
impl Clone for LiveSlot {
    fn clone(&self) -> Self {
        Self::default()
    }
}

#[derive(Serialize, Deserialize, Clone, Default)]
struct Secret {
    headers: Vec<(String, String)>,
    /// Merged into JSON request bodies (Plaid's access_token).
    body: Map<String, Value>,
    /// Google OAuth: a fresh access token is fetched with these.
    refresh: Option<Refresh>,
    #[serde(default)]
    imap: Option<crate::imap::Creds>,
    #[serde(default)]
    mcp: Option<crate::mcp::Server>,
}

#[derive(Serialize, Deserialize, Clone)]
struct Refresh {
    client_id: String,
    client_secret: String,
    refresh_token: String,
}

/// An origin the connection may reach: scheme, host and port.
struct Origin {
    https: bool,
    host: String,
    port: u16,
}

fn origin(s: &str) -> Result<Origin> {
    let u = url::Url::parse(s).with_context(|| format!("{s:?} is not a URL"))?;
    let https = match u.scheme() {
        "https" => true,
        "http" => false,
        _ => bail!("{s:?}: only https URLs"),
    };
    let host = u.host_str().context("the URL has no host")?.to_ascii_lowercase();
    Ok(Origin { https, port: u.port_or_known_default().unwrap_or(443), host })
}

fn origin_string(o: &Origin) -> String {
    let default = if o.https { 443 } else { 80 };
    let scheme = if o.https { "https" } else { "http" };
    if o.port == default {
        format!("{scheme}://{}", o.host)
    } else {
        format!("{scheme}://{}:{}", o.host, o.port)
    }
}

fn text<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v[k].as_str().map(str::trim).filter(|s| !s.is_empty())
}

fn need<'a>(v: &'a Value, k: &str, what: &str) -> Result<&'a str> {
    let s = text(v, k).ok_or_else(|| anyhow!("{what} is required"))?;
    ensure!(s.len() <= 4000, "{what} is too long");
    Ok(s)
}

fn clean_name(s: &str) -> Result<String> {
    let n: String = s.trim().to_ascii_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    ensure!(!n.is_empty() && n.len() <= 40, "a connection name is 1-40 letters, digits or _");
    Ok(n)
}

/// Check the auditee's input, ask the service who the credentials belong
/// to, and return the connection.
pub async fn connect(net: &Net, id: u32, v: &Value) -> Result<Connection> {
    let kind = text(v, "kind").unwrap_or("");
    let description = text(v, "description").unwrap_or("").to_string();
    ensure!(description.len() <= 2000, "the description is too long");
    let bearer = |t: &str| vec![("authorization".to_string(), format!("Bearer {t}"))];
    let (hosts, methods, secret, default_name): (Vec<String>, Vec<&str>, Secret, &str) = match kind {
        "slack" => {
            let t = need(v, "token", "a Slack token (xoxb-… or xoxp-…)")?;
            ensure!(t.starts_with("xox"), "Slack tokens start with xoxb- or xoxp-");
            (vec!["https://slack.com".into()], vec!["GET", "POST"], Secret { headers: bearer(t), ..Default::default() }, "slack")
        }
        "gmail" => {
            let mut secret = Secret::default();
            if let Some(rt) = text(v, "refresh_token") {
                secret.refresh = Some(Refresh {
                    client_id: need(v, "client_id", "the OAuth client ID")?.into(),
                    client_secret: need(v, "client_secret", "the OAuth client secret")?.into(),
                    refresh_token: rt.into(),
                });
            } else {
                secret.headers = bearer(need(v, "access_token", "an access token (or a refresh token with its client ID and secret)")?);
            }
            (vec!["https://gmail.googleapis.com".into()], vec!["GET"], secret, "gmail")
        }
        "plaid" => {
            let env = text(v, "environment").unwrap_or("production");
            ensure!(["production", "sandbox"].contains(&env), "environment is production or sandbox");
            let mut body = Map::new();
            body.insert("access_token".into(), json!(need(v, "access_token", "the Plaid access token")?));
            let headers = vec![
                ("plaid-client-id".to_string(), need(v, "client_id", "the Plaid client ID")?.to_string()),
                ("plaid-secret".to_string(), need(v, "secret", "the Plaid secret")?.to_string()),
            ];
            (vec![format!("https://{env}.plaid.com")], vec!["POST"], Secret { headers, body, ..Default::default() }, "plaid")
        }
        "github_api" => {
            let t = need(v, "token", "a GitHub token")?;
            (vec!["https://api.github.com".into()], vec!["GET"], Secret { headers: bearer(t), ..Default::default() }, "github")
        }
        "http" => {
            let base = need(v, "base_url", "the API's base URL")?;
            let o = origin(base)?;
            ensure!(net.is_dev() || (o.https && o.port == 443), "the base URL must be https on the standard port (443)");
            let mut headers = Vec::new();
            if let Some(h) = text(v, "header_name") {
                ensure!(h.len() <= 100 && h.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'), "a header name is letters, digits and -");
                headers.push((h.to_ascii_lowercase(), need(v, "header_value", "the header's value")?.to_string()));
            }
            let methods: Vec<&str> = match v["methods"].as_array() {
                Some(a) => a.iter().filter_map(|m| m.as_str()).filter_map(|m| METHODS.iter().copied().find(|k| k.eq_ignore_ascii_case(m))).collect(),
                None => vec!["GET"],
            };
            ensure!(!methods.is_empty(), "choose at least one HTTP method");
            (vec![origin_string(&o)], methods, Secret { headers, ..Default::default() }, "api")
        }
        "imap" => {
            let user = need(v, "username", "your email address")?;
            // The server can be left out for the common providers; any other
            // domain is most likely Google Workspace.
            let host = match text(v, "host") {
                Some(h) => h.to_ascii_lowercase(),
                None => crate::imap::server_for(user).to_string(),
            };
            ensure!(host.len() <= 253 && host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'), "the IMAP server is a host name, like imap.gmail.com");
            let port = v["port"].as_u64().unwrap_or(crate::net::IMAPS_PORT as u64) as u16;
            let tls = v["tls"].as_bool().unwrap_or(true);
            ensure!(net.is_dev() || (tls && port == crate::net::IMAPS_PORT), "IMAP must be over TLS on port 993");
            let creds = crate::imap::Creds {
                host: host.clone(),
                port,
                tls,
                user: user.into(),
                password: crate::imap::clean_password(&host, need(v, "password", "the app password")?),
            };
            let scheme = if tls { "imaps" } else { "imap" };
            (vec![format!("{scheme}://{host}:{port}")], vec!["read"], Secret { imap: Some(creds), ..Default::default() }, "email")
        }
        "mcp" => {
            let server = mcp_server(net, v)?;
            // Only the origin is recorded: some servers put a secret in the path.
            (vec![origin_string(&origin(need(v, "url", "the MCP server's URL")?)?)], vec![], Secret { headers: server.headers.clone(), mcp: Some(server), ..Default::default() }, "mcp")
        }
        _ => bail!("kind must be one of: {}", KINDS.join(", ")),
    };
    let mut c = Connection {
        rec: ConnectionRecord {
            id,
            kind: kind.into(),
            name: clean_name(text(v, "name").unwrap_or(default_name))?,
            hosts,
            methods: methods.iter().map(|m| m.to_string()).collect(),
            identity: None,
            description,
            connected_at_ms: now_ms(),
            calls: 0,
            tools: vec![],
        },
        secret,
        mcp_tools: vec![],
        mcp_server: String::new(),
        live: LiveSlot::default(),
        revoked: Default::default(),
    };
    let net = net.scoped(&c.hosts_only());
    c.refresh(&net).await?;
    c.rec.identity = c.identify(&net).await?;
    if let Some(server) = &c.secret.mcp {
        let (name, tools) = server.discover(&net).await?;
        let wanted: Vec<String> = v["tools"].as_array().map(|a| a.iter().filter_map(|t| t.as_str().map(String::from)).collect()).unwrap_or_default();
        ensure!(!wanted.is_empty(), "choose the tools the agent may use");
        for w in &wanted {
            ensure!(tools.iter().any(|t| &t.name == w), "the server has no tool named {w:?}");
        }
        c.mcp_tools = tools.into_iter().filter(|t| wanted.contains(&t.name)).collect();
        c.rec.tools = c.mcp_tools.iter().map(|t| t.name.clone()).collect();
        c.mcp_server = name;
    }
    Ok(c)
}

fn mcp_server(net: &Net, v: &Value) -> Result<crate::mcp::Server> {
    let url = need(v, "url", "the MCP server's URL")?;
    let o = origin(url)?;
    ensure!(net.is_dev() || (o.https && o.port == 443), "the MCP server's URL must be https on the standard port (443)");
    let u = url::Url::parse(url)?;
    let mut path = u.path().to_string();
    if let Some(q) = u.query() {
        path.push('?');
        path.push_str(q);
    }
    let mut headers = Vec::new();
    if let Some(t) = text(v, "token") {
        ensure!(t.len() <= 4000, "the token is too long");
        headers.push(("authorization".to_string(), format!("Bearer {t}")));
    } else if let Some(h) = text(v, "header_name") {
        ensure!(h.len() <= 100 && h.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'), "a header name is letters, digits and -");
        headers.push((h.to_ascii_lowercase(), need(v, "header_value", "the header's value")?.to_string()));
    }
    Ok(crate::mcp::Server { https: o.https, host: o.host, port: o.port, path, headers })
}

/// An MCP server's tools, for the auditee to choose from before connecting.
pub async fn preview(net: &Net, v: &Value) -> Result<Value> {
    let server = mcp_server(net, v)?;
    let net = net.scoped(&[server.host.clone()]);
    let (name, tools) = server.discover(&net).await?;
    Ok(json!({
        "server": name,
        "tools": tools.iter().map(|t| json!({"name": t.name, "description": t.description, "read_only": t.read_only})).collect::<Vec<_>>(),
    }))
}

/// The tools the agent gets for these connections, beyond the code tools.
pub fn agent_tools(conns: &[Connection]) -> Vec<(String, String, Value)> {
    let mut v = Vec::new();
    let http: Vec<&str> = conns.iter().filter(|c| c.is_http()).map(|c| c.rec.name.as_str()).collect();
    if !http.is_empty() {
        v.push(("http_request".to_string(), "Make one HTTP request to a connected service. The enclave adds the credentials; you never see them. Give the path (with any query in `query`), not a full URL. Responses over 40k characters are cut: use the API's paging and filters.".to_string(),
            json!({"type":"object","properties":{
                "connection":{"type":"string","enum":http},
                "method":{"type":"string","description":"GET, POST, ... (each connection allows some)"},
                "path":{"type":"string","description":"e.g. /api/conversations.history"},
                "query":{"type":"object","description":"Query parameters"},
                "body":{"description":"A JSON object, or a form-encoded string"}
            },"required":["connection","method","path"]})));
    }
    let mail: Vec<&str> = conns.iter().filter(|c| c.rec.kind == "imap").map(|c| c.rec.name.as_str()).collect();
    if !mail.is_empty() {
        v.push(("email".to_string(), "Read a connected mailbox (IMAP, read-only: nothing is marked read or changed). Actions: \"folders\" lists folders; \"search\" finds messages in a folder with IMAP SEARCH criteria (e.g. SINCE 1-Jan-2026 FROM \"bank.com\" SUBJECT \"invoice\"; on Gmail also X-GM-RAW \"has:attachment newer_than:1y\") and lists the newest with their uids; \"read\" shows one message's headers and text by uid. Attachments are listed, not opened.".to_string(),
            json!({"type":"object","properties":{
                "connection":{"type":"string","enum":mail},
                "action":{"type":"string","enum":["folders","search","read"]},
                "folder":{"type":"string","description":"Default INBOX. On Gmail, \"[Gmail]/All Mail\" has everything."},
                "query":{"type":"string","description":"search: IMAP SEARCH criteria, ASCII; default ALL"},
                "max_results":{"type":"integer","description":"search: at most this many (newest first; default 30, max 100)"},
                "uid":{"type":"integer","description":"read: the message's uid from search"}
            },"required":["connection","action"]})));
    }
    for c in conns.iter().filter(|c| c.rec.kind == "mcp") {
        for t in &c.mcp_tools {
            let name = crate::mcp::agent_name(&c.rec.name, &t.name);
            if v.iter().any(|(n, _, _)| n == &name) {
                continue;
            }
            v.push((name, format!("[{} (MCP server)] {}", c.rec.name, t.description), t.schema.clone()));
        }
    }
    v
}

/// Run one of the agent_tools; None if `tool` isn't one of them.
pub async fn dispatch(conns: &mut [(Connection, Net)], tool: &str, args: &Value) -> Option<String> {
    let pick = |conns: &mut [(Connection, Net)], ok: &dyn Fn(&Connection) -> bool| -> std::result::Result<usize, String> {
        let name = args["connection"].as_str().unwrap_or("");
        conns.iter().position(|(c, _)| c.rec.name == name && ok(c)).ok_or_else(|| {
            let names: Vec<&str> = conns.iter().filter(|(c, _)| ok(c)).map(|(c, _)| c.rec.name.as_str()).collect();
            format!("error: no such connection {name:?}; these work with {tool}: {}", names.join(", "))
        })
    };
    let out = match tool {
        "http_request" => match pick(conns, &|c| c.is_http()) {
            Ok(i) => {
                let (c, n) = &mut conns[i];
                if c.is_revoked() {
                    return Some(REVOKED.into());
                }
                c.request(n, args).await
            }
            Err(e) => return Some(e),
        },
        "email" => match pick(conns, &|c| c.rec.kind == "imap") {
            Ok(i) => {
                let (c, n) = &mut conns[i];
                if c.is_revoked() {
                    return Some(REVOKED.into());
                }
                c.rec.calls += 1;
                let creds = c.secret.imap.clone().expect("imap connection");
                crate::imap::request(n, &creds, args).await.map(|t| c.mask(t))
            }
            Err(e) => return Some(e),
        },
        _ => {
            let i = conns.iter().position(|(c, _)| c.mcp_tools.iter().any(|t| crate::mcp::agent_name(&c.rec.name, &t.name) == tool))?;
            let (c, n) = &mut conns[i];
            if c.is_revoked() {
                return Some(REVOKED.into());
            }
            let t = c.mcp_tools.iter().find(|t| crate::mcp::agent_name(&c.rec.name, &t.name) == tool).expect("found").name.clone();
            c.rec.calls += 1;
            let server = c.secret.mcp.clone().expect("mcp connection");
            server.call_tool(n, &mut c.live.0, &t, args.clone()).await.map(|t| c.mask(t))
        }
    };
    Some(out.unwrap_or_else(|e| format!("error: {e:#}")))
}

impl Connection {
    /// Stop every copy of this connection (in running agents too) from
    /// making further requests.
    pub fn revoke(&self) {
        self.revoked.store(true, Ordering::SeqCst);
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::SeqCst)
    }

    fn is_http(&self) -> bool {
        !matches!(self.rec.kind.as_str(), "imap" | "mcp")
    }

    fn hosts_only(&self) -> Vec<String> {
        if let Some(i) = &self.secret.imap {
            return vec![i.host.clone()];
        }
        let mut h: Vec<String> = self.rec.hosts.iter().filter_map(|o| origin(o).ok()).map(|o| o.host).collect();
        if self.secret.refresh.is_some() {
            h.push("oauth2.googleapis.com".into());
        }
        h
    }

    /// The enclave's egress for this connection.
    pub fn net(&self, net: &Net) -> Net {
        net.scoped(&self.hosts_only())
    }

    /// Get a fresh Google access token, if this connection refreshes.
    async fn refresh(&mut self, net: &Net) -> Result<()> {
        let Some(r) = &self.secret.refresh else { return Ok(()) };
        let form = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", &r.client_id)
            .append_pair("client_secret", &r.client_secret)
            .append_pair("refresh_token", &r.refresh_token)
            .append_pair("grant_type", "refresh_token")
            .finish();
        let resp = net
            .request_full("POST", true, "oauth2.googleapis.com", 443, "/token", &[("content-type", "application/x-www-form-urlencoded"), ("user-agent", "attest-enclave")], form.into_bytes(), TIMEOUT)
            .await?;
        ensure!(resp.status == 200, "Google refused the refresh token (HTTP {})", resp.status);
        let v: Value = serde_json::from_slice(&resp.body)?;
        let t = v["access_token"].as_str().context("Google returned no access token")?;
        self.secret.headers = vec![("authorization".into(), format!("Bearer {t}"))];
        Ok(())
    }

    /// Ask the service who these credentials belong to.
    async fn identify(&self, net: &Net) -> Result<Option<String>> {
        if let Some(i) = &self.secret.imap {
            crate::imap::check(net, i).await?;
            return Ok(Some(format!("mailbox {} at {} (the server accepted its password)", i.user, i.host)));
        }
        let get = |method: &'static str, path: &'static str, body: Value| async move {
            let r = self.send(net, method, 0, path, body).await?;
            let v: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
            Ok::<_, anyhow::Error>((r.status, v))
        };
        Ok(match self.rec.kind.as_str() {
            "slack" => {
                let (_, v) = get("POST", "/api/auth.test", Value::Null).await?;
                ensure!(v["ok"] == json!(true), "Slack refused the token: {}", v["error"].as_str().unwrap_or("unknown error"));
                Some(format!(
                    "Slack workspace {} ({}, {}), as {}",
                    v["team"].as_str().unwrap_or("?"),
                    v["team_id"].as_str().unwrap_or("?"),
                    v["url"].as_str().unwrap_or("?"),
                    v["user"].as_str().unwrap_or("?")
                ))
            }
            "gmail" => {
                let (st, v) = get("GET", "/gmail/v1/users/me/profile", Value::Null).await?;
                ensure!(st == 200, "Gmail refused the token (HTTP {st}); it needs the gmail.readonly scope");
                Some(format!("Gmail mailbox {}", v["emailAddress"].as_str().context("Gmail gave no address")?))
            }
            "plaid" => {
                let (st, v) = get("POST", "/item/get", json!({})).await?;
                ensure!(st == 200, "Plaid refused the credentials: {}", v["error_message"].as_str().unwrap_or("unknown error"));
                let inst = v["item"]["institution_id"].as_str().unwrap_or("?").to_string();
                let (_, n) = self
                    .send(net, "POST", 0, "/institutions/get_by_id", json!({"institution_id": inst, "country_codes": ["US", "GB", "CA"]}))
                    .await
                    .map(|r| (r.status, serde_json::from_slice::<Value>(&r.body).unwrap_or(Value::Null)))
                    .unwrap_or((0, Value::Null));
                let name = n["institution"]["name"].as_str().map(|s| format!("{s} ")).unwrap_or_default();
                Some(format!("Plaid item {} at {name}({inst}), {}", v["item"]["item_id"].as_str().unwrap_or("?"), self.rec.hosts[0]))
            }
            "github_api" => {
                let (st, v) = get("GET", "/user", Value::Null).await?;
                ensure!(st == 200, "GitHub refused the token (HTTP {st})");
                Some(format!("GitHub account {}", v["login"].as_str().unwrap_or("?")))
            }
            _ => None,
        })
    }

    async fn send(&self, net: &Net, method: &str, host: usize, path_q: &str, body: Value) -> Result<crate::net::HttpResponse> {
        let o = origin(&self.rec.hosts[host])?;
        let mut headers: Vec<(&str, &str)> = vec![("user-agent", "attest-enclave"), ("accept", "application/json")];
        for (k, v) in &self.secret.headers {
            headers.push((k, v));
        }
        let bytes = match body {
            Value::Null => Vec::new(),
            Value::String(s) => {
                headers.push(("content-type", "application/x-www-form-urlencoded"));
                s.into_bytes()
            }
            Value::Object(mut m) => {
                for (k, v) in &self.secret.body {
                    m.insert(k.clone(), v.clone());
                }
                headers.push(("content-type", "application/json"));
                serde_json::to_vec(&m)?
            }
            _ => bail!("body must be a JSON object or a string"),
        };
        net.request_full(method, o.https, &o.host, o.port, path_q, &headers, bytes, TIMEOUT).await
    }

    /// One request by the agent. Errors come back as text for the model.
    pub async fn request(&mut self, net: &Net, args: &Value) -> Result<String> {
        let method = args["method"].as_str().unwrap_or("GET").to_ascii_uppercase();
        ensure!(self.rec.methods.contains(&method), "{} allows only {}", self.rec.name, self.rec.methods.join(", "));
        let path = args["path"].as_str().unwrap_or("/");
        ensure!(path.starts_with('/') && !path.starts_with("//") && path.len() <= 2000 && !path.chars().any(|c| c.is_whitespace() || c == '#'), "path must start with / (no scheme or host)");
        let mut path_q = path.to_string();
        if let Some(q) = args["query"].as_object() {
            let mut ser = url::form_urlencoded::Serializer::new(String::new());
            for (k, v) in q {
                let v = match v {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                ser.append_pair(k, &v);
            }
            let q = ser.finish();
            if !q.is_empty() {
                path_q.push(if path_q.contains('?') { '&' } else { '?' });
                path_q.push_str(&q);
            }
        }
        let body = match &args["body"] {
            Value::Null => if self.secret.body.is_empty() || method == "GET" { Value::Null } else { json!({}) },
            b => b.clone(),
        };
        let mut r = self.send(net, &method, 0, &path_q, body.clone()).await?;
        if r.status == 401 && self.secret.refresh.is_some() {
            ensure!(!self.is_revoked(), "this connection was removed by the auditee");
            self.refresh(net).await?;
            r = self.send(net, &method, 0, &path_q, body).await?;
        }
        self.rec.calls += 1;
        let ctype = r.header("content-type").unwrap_or("").to_string();
        let text = self.mask(String::from_utf8_lossy(&r.body).into_owned());
        Ok(format!("HTTP {} {}\n\n{text}", r.status, ctype))
    }

    /// Hide echoed credentials and cut long output.
    fn mask(&self, mut text: String) -> String {
        for secret in self.secret_values() {
            if secret.len() >= 8 {
                text = text.replace(&secret, "[credential]");
            }
        }
        let total = text.chars().count();
        if total > MAX_RESPONSE_CHARS {
            text = text.chars().take(MAX_RESPONSE_CHARS).collect();
            text.push_str(&format!("\n[cut: showing {MAX_RESPONSE_CHARS} of {total} characters; ask for less, e.g. with paging or filters]"));
        }
        text
    }

    fn secret_values(&self) -> Vec<String> {
        let mut v: Vec<String> = self.secret.headers.iter().map(|(_, v)| v.trim_start_matches("Bearer ").to_string()).collect();
        v.extend(self.secret.body.values().filter_map(|x| x.as_str().map(String::from)));
        if let Some(r) = &self.secret.refresh {
            v.extend([r.client_secret.clone(), r.refresh_token.clone()]);
        }
        if let Some(i) = &self.secret.imap {
            v.push(i.password.clone());
        }
        v
    }

    /// How the agent's prompt describes it.
    pub fn describe(&self) -> String {
        if self.rec.kind == "imap" {
            return self.with_desc(format!("- {} (a mailbox over IMAP, read-only; use the email tool): {}", self.rec.name, self.rec.identity.clone().unwrap_or_default()));
        }
        if self.rec.kind == "mcp" {
            return self.with_desc(format!(
                "- {} (an MCP server at {}{}; its tools are named {}__TOOL): {}",
                self.rec.name,
                self.rec.hosts.join(", "),
                if self.mcp_server.is_empty() { String::new() } else { format!(", calling itself {:?}", self.mcp_server) },
                self.rec.name,
                self.rec.tools.join(", ")
            ));
        }
        let mut s = format!(
            "- {} ({}): {}; methods {}",
            self.rec.name,
            match self.rec.kind.as_str() {
                "slack" => "the Slack Web API",
                "gmail" => "the Gmail API, read-only",
                "plaid" => "the Plaid API; the access token is added to every request body",
                "github_api" => "the GitHub REST API",
                _ => "an HTTP API",
            },
            self.rec.hosts.join(", "),
            self.rec.methods.join(", ")
        );
        if let Some(i) = &self.rec.identity {
            s.push_str(&format!("; credentials belong to {i}"));
        }
        self.with_desc(s)
    }

    fn with_desc(&self, mut s: String) -> String {
        if !self.rec.description.is_empty() {
            s.push_str(&format!("\n  The auditee's description: {}", self.rec.description.replace('\n', " ")));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_and_names() {
        assert_eq!(origin_string(&origin("https://API.example.com/v1").unwrap()), "https://api.example.com");
        assert_eq!(origin_string(&origin("http://127.0.0.1:9000").unwrap()), "http://127.0.0.1:9000");
        assert!(origin("ftp://x").is_err());
        assert_eq!(clean_name("My API").unwrap(), "my_api");
        assert!(clean_name("").is_err());
    }

    #[tokio::test]
    async fn removal_reaches_running_copies() {
        let c = Connection {
            rec: ConnectionRecord { id: 1, kind: "http".into(), name: "api".into(), hosts: vec!["https://example.com".into()], methods: vec!["GET".into()], identity: None, description: String::new(), connected_at_ms: 0, calls: 0, tools: vec![] },
            secret: Secret::default(),
            mcp_tools: vec![],
            mcp_server: String::new(),
            live: LiveSlot::default(),
            revoked: Default::default(),
        };
        let copy = c.clone();
        c.revoke();
        let net = crate::net::Net::new(true, String::new()).unwrap();
        let mut conns = vec![(copy, net)];
        let out = dispatch(&mut conns, "http_request", &json!({"connection": "api", "path": "/"})).await;
        assert_eq!(out.as_deref(), Some(REVOKED));
        assert_eq!(conns[0].0.rec.calls, 0);
    }
}
