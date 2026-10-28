#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]
//! Real agent harnesses (OpenAI Codex, Claude Code, pi) run in the native jail.
//!
//! The harness gets a shell with the repository read-only at /repo and a
//! 20 MB scratch /work, and reaches its model only through the per-run
//! proxy (modelproxy.rs). It writes its verdict to /work/verdict.json.

use crate::bundle::Bundle;
use crate::modelproxy::ModelProxy;
use crate::run::AgentOutput;
use attest_core::*;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

// Pinned in build/Dockerfile (and build/pi/package-lock.json for pi).
pub const CODEX_VERSION: &str = "0.164.0";
pub const CLAUDE_CODE_VERSION: &str = "2.1.311";
pub const PI_VERSION: &str = "0.73.1";
pub const IMAGE_ROOT: &str = "/opt/jailroot";
/// Loopback port inside the jail's network namespace that reaches the proxy.
const PROXY_PORT: u16 = 8080;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Agent {
    Codex,
    ClaudeCode,
    Pi,
}

pub const AGENTS: [Agent; 3] = [Agent::Codex, Agent::ClaudeCode, Agent::Pi];

impl Agent {
    pub fn parse(s: &str) -> Option<Agent> {
        AGENTS.into_iter().find(|a| a.id() == s)
    }
    pub fn id(self) -> &'static str {
        match self {
            Agent::Codex => "codex",
            Agent::ClaudeCode => "claude-code",
            Agent::Pi => "pi",
        }
    }
    pub fn version(self) -> &'static str {
        match self {
            Agent::Codex => CODEX_VERSION,
            Agent::ClaudeCode => CLAUDE_CODE_VERSION,
            Agent::Pi => PI_VERSION,
        }
    }
    /// How certificates and /api/info name it: "codex 0.164.0".
    pub fn label(self) -> String {
        format!("{} {}", self.id(), self.version())
    }
    fn binary(self) -> &'static str {
        match self {
            Agent::Codex => "/usr/bin/codex",
            Agent::ClaudeCode => "/usr/bin/claude",
            Agent::Pi => "/usr/bin/pi",
        }
    }
    fn installed(self) -> bool {
        cfg!(target_os = "linux")
            && std::path::Path::new(&format!("{IMAGE_ROOT}{}", self.binary())).exists()
    }
    /// The model API this harness uses with `target`, if it can use any.
    fn api_for(self, target: &crate::llm::Target) -> Option<crate::llm::Api> {
        use crate::llm::{Api, Wire};
        let want = match (self, target.wire) {
            (Agent::Codex, _) => Api::Responses,
            (Agent::ClaudeCode, _) => Api::Messages,
            (Agent::Pi, Wire::Anthropic) => Api::Messages,
            (Agent::Pi, Wire::Openai) => Api::Responses,
        };
        target.apis().contains(&want).then_some(want)
    }
}

pub fn available() -> Vec<String> {
    let mut v = vec!["builtin".to_string()];
    v.extend(
        AGENTS
            .into_iter()
            .filter(|a| a.installed())
            .map(Agent::label),
    );
    v
}

pub fn supports(agent: &str, target: &crate::llm::Target) -> anyhow::Result<()> {
    if agent == "builtin" {
        return Ok(());
    }
    let Some(a) = Agent::parse(agent) else {
        anyhow::bail!("unknown agent {agent:?} (builtin, codex, claude-code, pi)");
    };
    anyhow::ensure!(
        a.installed(),
        "this server does not have the {agent} harness"
    );
    anyhow::ensure!(
        a.api_for(target).is_some(),
        "{agent} needs {} models, and {} serves {} here",
        match a {
            Agent::Codex => "OpenAI-API (Responses)",
            Agent::ClaudeCode => "Anthropic-API (Messages)",
            Agent::Pi => "OpenAI- or Anthropic-API",
        },
        target.provider.as_str(),
        if target.wire == crate::llm::Wire::Anthropic { "Anthropic's API" } else { "the OpenAI API" },
    );
    Ok(())
}

pub fn agent_prompt(
    question: &str,
    format: &AnswerFormat,
    previous: Option<(&Verdict, &str)>,
) -> String {
    let mut p = format!(
        "{}\n\nYou are running as a command-line coding agent with a shell. The repository is at /repo (read-only, your working directory). /work and /tmp are writable scratch space, 20 MB each. There is no network access except to your model; do not try to install anything.\n\nQuestion from the auditor:\n<question>\n{question}\n</question>\n",
        attest_core::harness::SYSTEM_PROMPT.split("\n\nTools:").next().unwrap_or("")
    );
    if let Some((v, msg)) = previous {
        p.push_str(&format!(
            "\nYour previous verdict was: {} (confidence {:.2}).\nPrevious summary:\n{}\n\nFollow-up message from the auditor:\n<message>\n{msg}\n</message>\n",
            serde_json::to_string(&v.answer).unwrap_or_default(),
            v.confidence,
            v.summary
        ));
    }
    p.push_str(&format!("\nAnswer format agreed with the auditee: {}. The enclave rejects any verdict outside it.\n", format.describe()));
    p.push_str(match format {
        AnswerFormat::YesNo => "\nWhen you are done, write your verdict as JSON to /work/verdict.json: {\"answer\": \"yes\" | \"no\" | \"inconclusive\"} and nothing else. Then stop.",
        AnswerFormat::Choice { .. } => "\nWhen you are done, write your verdict as JSON to /work/verdict.json: {\"choice\": \"<exactly one of the options>\"} and nothing else. Then stop.",
        AnswerFormat::Text { .. } => "\nWhen you are done, write your verdict as JSON to /work/verdict.json with exactly these keys: \"answer\" (one of \"yes\", \"no\", \"inconclusive\", \"needs_clarification\"), \"confidence\" (0 to 1), \"summary\" (for the auditor, per the rules above, within the byte limit), and \"clarification_request\" (a string, only with needs_clarification). Then stop.",
    });
    p
}

fn parse_verdict(text: &str, format: &AnswerFormat) -> Result<Verdict, String> {
    let start = text.find('{').ok_or("no JSON verdict")?;
    let end = text.rfind('}').ok_or("no JSON verdict")?;
    let v: Value = serde_json::from_str(&text[start..=end])
        .map_err(|_| "verdict is not valid JSON".to_string())?;
    crate::run::parse_verdict(&v, format).map_err(|e| e.to_string())
}

#[allow(clippy::too_many_arguments)]
pub async fn run_agent(
    agent: Agent,
    net: crate::net::Net,
    run_id: &str,
    bundle: &Arc<Bundle>,
    target: crate::llm::Target,
    model: &str,
    api_key: &str,
    routing: crate::llm::Routing,
    prompt: String,
    format: &AnswerFormat,
    timeout: Duration,
    progress: Arc<dyn Fn(Vec<Value>) + Send + Sync>,
) -> AgentOutput {
    let fail = |msg: String| AgentOutput {
        turns: vec![],
        verdict: None,
        outcome: Outcome::Error { message: msg },
        activity: Activity::default(),
        files_read: BTreeMap::new(),
        response_models: vec![],
        upstream_providers: vec![],
        key_owner: None,
    };
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            agent, net, run_id, bundle, target, model, api_key, routing, prompt, format, timeout,
            progress,
        );
        return fail("agent harnesses need a Linux enclave".into());
    }
    #[cfg(target_os = "linux")]
    {
        let p2 = progress.clone();
        let scratch = format!("/jails/{run_id}");
        let _ = std::fs::create_dir_all(&scratch);
        let socket = format!("{scratch}/proxy.sock");
        let proxy = match ModelProxy::start(
            net,
            target.clone(),
            model.to_string(),
            api_key.to_string(),
            routing,
            &socket,
            Arc::new(move |e| p2(vec![e])),
        )
        .await
        {
            Ok(p) => p,
            Err(e) => return fail(format!("model proxy: {e:#}")),
        };
        let repo = format!("{scratch}/repo");
        progress(vec![
            json!({"type": "harness", "content": format!("Preparing the repository for {} ({} files)...", agent.label(), bundle.info.file_count)}),
        ]);
        if let Err(e) = crate::jail::materialize(bundle, &repo).await {
            crate::jail::unmount(&repo);
            return fail(format!("preparing the repository: {e:#}"));
        }
        let (argv, env) = command(agent, &target, model, &proxy.token, prompt);
        // Each run gets its own cgroup (memory, process and CPU caps) and
        // user id. Without the cgroup there's no dependable way to end the
        // run, so no cgroup, no run.
        let cgroup = match crate::cgroups::RunCgroup::create(run_id, &run_limits()) {
            Ok(c) => c,
            Err(e) => {
                crate::jail::unmount(&repo);
                let _ = std::fs::remove_dir_all(&scratch);
                return fail(format!("setting up the run's resource limits: {e:#}"));
            }
        };
        let spec = crate::jail::Spec {
            uid: next_uid(),
            cgroup_procs: cgroup.procs_files(),
            repo: repo.clone(),
            image_root: IMAGE_ROOT.into(),
            scratch: scratch.clone(),
            argv,
            env,
            cwd: "/repo".into(),
            work_mib: 20,
            collect: vec!["verdict.json".into(), "last-message.txt".into()],
            proxy_socket: socket.clone(),
            proxy_port: PROXY_PORT,
        };
        let started = std::time::SystemTime::now() - Duration::from_secs(1);
        let out = run_jailed(&spec, timeout, progress.clone()).await;
        // Whatever the agent left running (it may have detached from the
        // executor) dies here, before the repository is unmounted.
        tokio::task::spawn_blocking(move || drop(cgroup)).await.ok();
        let read = crate::jail::accessed_since(&repo, started);
        crate::jail::unmount(&repo);
        let _ = std::fs::remove_dir_all(&scratch);

        let usage = proxy.usage.lock().unwrap().clone();
        let mut files_read = BTreeMap::new();
        for p in read {
            if let Some(e) = bundle.files.get(&p) {
                files_read.insert(p, e.digest);
            }
        }
        let mut activity = Activity {
            llm_calls: usage.calls,
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
            files_read: files_read.len() as u64,
            files_read_commitment: tree::files_commitment(files_read.iter()),
            ..Default::default()
        };
        activity.tool_calls = usage.calls.saturating_sub(1);
        progress(vec![
            json!({"type": "files_read", "paths": files_read.keys().collect::<Vec<_>>()}),
        ]);
        let (verdict, outcome) = match out {
            Ok((exit, files)) => {
                let parsed = match files.get("verdict.json") {
                    Some(t) => parse_verdict(t, format),
                    None => files
                        .get("last-message.txt")
                        .map(|t| parse_verdict(t, format))
                        .unwrap_or(Err("no verdict file".into())),
                };
                match (parsed, exit) {
                    (Ok(v), _) => (Some(v), Outcome::Completed),
                    (Err(why), 0) => {
                        // `why` can quote what the model wrote, so it goes
                        // only to the auditee's trace, never into the outcome.
                        let why: String = why.chars().take(2000).collect();
                        progress(vec![json!({"type": "error", "content": format!("invalid verdict: {why}")})]);
                        (
                            None,
                            Outcome::Error {
                                message: format!("{} did not produce a valid verdict", agent.id()),
                            },
                        )
                    }
                    (Err(_), c) => (
                        None,
                        Outcome::Error {
                            message: format!("{} exited with status {c}", agent.id()),
                        },
                    ),
                }
            }
            Err(e) => (None, Outcome::Error { message: e }),
        };
        AgentOutput {
            turns: vec![],
            verdict,
            outcome,
            activity,
            files_read,
            response_models: usage.models.into_iter().collect(),
            upstream_providers: usage.upstream.into_iter().collect(),
            key_owner: usage.key_owner,
        }
    }
}

/// The command line and environment for `agent`, talking to its model only
/// through the proxy at 127.0.0.1:PROXY_PORT with the per-run `token`.
///
/// Each harness is kept from loading instructions or plugins from the
/// repository (AGENTS.md, CLAUDE.md, .claude/settings.json hooks, pi
/// extensions), which the auditee controls; it reads them only as code.
#[cfg(target_os = "linux")]
fn command(
    agent: Agent,
    target: &crate::llm::Target,
    model: &str,
    token: &str,
    prompt: String,
) -> (Vec<String>, Vec<(String, String)>) {
    let base = format!("http://127.0.0.1:{PROXY_PORT}");
    let mut env: Vec<(String, String)> = vec![
        ("PATH".into(), "/usr/bin:/bin".into()),
        ("HOME".into(), "/work".into()),
        ("TMPDIR".into(), "/tmp".into()),
        ("NO_COLOR".into(), "1".into()),
        ("TERM".into(), "dumb".into()),
        ("SHELL".into(), "/bin/bash".into()),
    ];
    let s = |x: &str| x.to_string();
    let argv = match agent {
        Agent::Codex => {
            env.push(("CODEX_HOME".into(), "/work".into()));
            env.push(("ATTEST_PROXY_TOKEN".into(), token.into()));
            vec![
                s("/usr/bin/codex"), s("exec"), s("--skip-git-repo-check"),
                s("--dangerously-bypass-approvals-and-sandbox"), s("--color"), s("never"),
                s("-m"), s(model),
                s("-c"), s("model_provider=\"attest\""),
                s("-c"), format!("model_providers.attest={{ name = \"attest\", base_url = \"{base}/v1\", env_key = \"ATTEST_PROXY_TOKEN\", wire_api = \"responses\" }}"),
                s("-c"), s("check_for_update_on_startup=false"),
                s("-c"), s("project_doc_max_bytes=0"),
                s("--output-last-message"), s("/work/last-message.txt"),
                prompt,
            ]
        }
        Agent::ClaudeCode => {
            for (k, v) in [
                ("ANTHROPIC_BASE_URL", base.as_str()),
                ("ANTHROPIC_API_KEY", token),
                ("ANTHROPIC_SMALL_FAST_MODEL", model),
                ("ANTHROPIC_DEFAULT_HAIKU_MODEL", model),
                ("CLAUDE_CONFIG_DIR", "/work/.claude"),
                ("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1"),
                ("DISABLE_AUTOUPDATER", "1"),
                ("DISABLE_TELEMETRY", "1"),
            ] {
                env.push((k.into(), v.into()));
            }
            // stream-json goes to stderr, which becomes the live trace.
            vec![
                s("/bin/sh"),
                s("-c"),
                s("exec /usr/bin/claude \"$@\" 1>&2"),
                s("sh"),
                // (--disallowedTools takes a list, so another flag must follow it.)
                s("--disallowedTools"),
                s("WebSearch,WebFetch"),
                s("-p"),
                s("--bare"),
                s("--setting-sources"),
                s("user"),
                s("--strict-mcp-config"),
                s("--no-session-persistence"),
                s("--permission-mode"),
                s("bypassPermissions"),
                s("--output-format"),
                s("stream-json"),
                s("--verbose"),
                s("--model"),
                s(model),
                prompt,
            ]
        }
        Agent::Pi => {
            let (api, url) = match agent.api_for(target) {
                Some(crate::llm::Api::Messages) => ("anthropic-messages", base.clone()),
                _ => ("openai-responses", format!("{base}/v1")),
            };
            let models = json!({"providers": {"attest": {
                "baseUrl": url, "api": api, "apiKey": "ATTEST_PROXY_TOKEN",
                "models": [{"id": model, "reasoning": true, "contextWindow": 200000, "maxTokens": 16000}],
            }}});
            for (k, v) in [
                ("PI_CODING_AGENT_DIR", "/work/.pi/agent"),
                ("ATTEST_PROXY_TOKEN", token),
                ("PI_OFFLINE", "1"),
                ("PI_TELEMETRY", "0"),
                ("PI_SKIP_VERSION_CHECK", "1"),
            ] {
                env.push((k.into(), v.into()));
            }
            env.push(("ATTEST_PI_MODELS".into(), models.to_string()));
            // pi reads its provider from a file; /work starts empty.
            vec![
                s("/bin/sh"), s("-c"),
                s("mkdir -p \"$PI_CODING_AGENT_DIR\" && printf '%s' \"$ATTEST_PI_MODELS\" > \"$PI_CODING_AGENT_DIR/models.json\" && exec /usr/bin/pi \"$@\" 1>&2"),
                s("sh"),
                // Text mode: pi's json mode repeats the whole message on every
                // token. The proxy already records each request in the trace.
                s("-p"), s("--provider"), s("attest"), s("--model"), s(model),
                s("--no-session"), s("--no-context-files"), s("--no-extensions"), s("--no-skills"),
                s("--no-prompt-templates"), s("--no-themes"), s("--offline"),
                prompt,
            ]
        }
    };
    (argv, env)
}

/// Run the jail executor, streaming its log into the trace.
#[cfg(target_os = "linux")]
async fn run_jailed(
    spec: &crate::jail::Spec,
    timeout: Duration,
    progress: Arc<dyn Fn(Vec<Value>) + Send + Sync>,
) -> Result<(i32, BTreeMap<String, String>), String> {

    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut child = tokio::process::Command::new(exe)
        .arg("--jail-exec")
        .arg(serde_json::to_string(spec).unwrap())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("starting the jail: {e}"))?;
    let stderr = child.stderr.take().unwrap();
    let p2 = progress.clone();
    let log_task = tokio::spawn(async move {
        let mut lines = BoundedLines::new(stderr, 4000);
        let mut budget = 400_000usize;
        let mut batch = Vec::new();
        while let Some(l) = lines.next_line().await {
            if budget == 0 {
                continue;
            }
            let l: String = l.chars().take(4000).collect();
            // Charge per line too, so empty lines can't make unbounded updates.
            budget = budget.saturating_sub(l.len() + 200);
            batch.push(l);
            if batch.len() >= 20 {
                p2(vec![
                    json!({"type": "harness_log", "content": batch.join("\n")}),
                ]);
                batch.clear();
            }
        }
        if !batch.is_empty() {
            p2(vec![
                json!({"type": "harness_log", "content": batch.join("\n")}),
            ]);
        }
    });
    // Only the executor writes stdout (the agent's goes to stderr); the
    // result line holds at most a few collected files.
    let mut stdout = BoundedLines::new(child.stdout.take().unwrap(), 4 << 20);
    let read_out = async {
        let mut result = None;
        while let Some(l) = stdout.next_line().await {
            if let Some(r) = l.strip_prefix(crate::jail::RESULT_MARKER) {
                result = serde_json::from_str::<Value>(r).ok();
            }
        }
        result
    };
    let r = tokio::time::timeout(timeout, async {
        let res = read_out.await;
        let _ = child.wait().await;
        res
    })
    .await;
    if r.is_err() {
        // The caller then kills everything in the run's cgroup.
        let _ = child.kill().await;
    }
    let _ = tokio::time::timeout(Duration::from_secs(10), log_task).await;
    match r {
        Err(_) => Err(format!(
            "the agent did not finish within {} minutes",
            timeout.as_secs() / 60
        )),
        Ok(None) => Err("the jail ended without a result".into()),
        Ok(Some(v)) => {
            let files = v["files"]
                .as_object()
                .map(|m| {
                    m.iter()
                        .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                        .collect()
                })
                .unwrap_or_default();
            Ok((v["exit"].as_i64().unwrap_or(-1) as i32, files))
        }
    }
}

/// Memory, process and CPU caps for one jailed run: a share of the
/// enclave's memory that leaves room for the service and other runs.
#[cfg(target_os = "linux")]
fn run_limits() -> crate::cgroups::Limits {
    let total = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|m| {
            m.lines()
                .find(|l| l.starts_with("MemTotal:"))
                .and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
        })
        .map(|kib| kib * 1024)
        .unwrap_or(8 << 30);
    crate::cgroups::Limits {
        memory_bytes: (total / 5).clamp(1 << 30, 4 << 30),
        pids: 512,
        cpus: 1.0,
    }
}

/// A user id for the next jailed run, distinct from any other run that
/// could be going at the same time.
#[cfg(target_os = "linux")]
fn next_uid() -> u32 {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    200_000 + NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % 50_000
}

/// Lines from a pipe, each cut to `max` bytes; the rest of an overlong line
/// is skipped without being buffered.
#[cfg(target_os = "linux")]
struct BoundedLines<R> {
    r: R,
    buf: Vec<u8>,
    pending: std::collections::VecDeque<String>,
    max: usize,
    skipping: bool,
    eof: bool,
}

#[cfg(target_os = "linux")]
impl<R: tokio::io::AsyncRead + Unpin> BoundedLines<R> {
    fn new(r: R, max: usize) -> Self {
        Self { r, buf: Vec::new(), pending: Default::default(), max, skipping: false, eof: false }
    }

    async fn next_line(&mut self) -> Option<String> {
        use tokio::io::AsyncReadExt;
        loop {
            if let Some(l) = self.pending.pop_front() {
                return Some(l);
            }
            if self.eof {
                if self.buf.is_empty() {
                    return None;
                }
                return Some(String::from_utf8_lossy(&std::mem::take(&mut self.buf)).into_owned());
            }
            let mut chunk = [0u8; 16384];
            let n = self.r.read(&mut chunk).await.unwrap_or(0);
            if n == 0 {
                self.eof = true;
                continue;
            }
            for &b in &chunk[..n] {
                if b == b'\n' {
                    if !self.skipping || !self.buf.is_empty() {
                        self.pending.push_back(String::from_utf8_lossy(&std::mem::take(&mut self.buf)).into_owned());
                    }
                    self.skipping = false;
                } else if self.buf.len() < self.max {
                    self.buf.push(b);
                } else {
                    self.skipping = true;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_parsing() {
        let text = AnswerFormat::default();
        let v = parse_verdict(
            "done.\n{\"answer\": \"no\", \"confidence\": 0.7, \"summary\": \"s\"}\n",
            &text,
        )
        .unwrap();
        assert_eq!(v.answer, Answer::No);
        assert!(parse_verdict("{\"answer\": \"maybe\", \"summary\": \"s\"}", &text).is_err());
        let yn = parse_verdict(
            "{\"answer\": \"yes\", \"summary\": \"secret code here\"}",
            &AnswerFormat::YesNo,
        )
        .unwrap();
        assert!(yn.summary.is_empty(), "strict formats drop text");
        let ch = AnswerFormat::Choice {
            options: vec!["a".into(), "b".into()],
        };
        assert_eq!(
            parse_verdict("{\"choice\": \"b\"}", &ch)
                .unwrap()
                .choice
                .as_deref(),
            Some("b")
        );
        assert!(parse_verdict("{\"choice\": \"c\"}", &ch).is_err());
        let short = AnswerFormat::Text { max_bytes: 5 };
        assert!(parse_verdict("{\"answer\": \"no\", \"summary\": \"too long\"}", &short).is_err());
    }
}
