#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]
//! Real agent harnesses (currently OpenAI Codex) run in the native jail.
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

pub const CODEX_VERSION: &str = "0.164.0";
pub const IMAGE_ROOT: &str = "/opt/jailroot";
/// Loopback port inside the jail's network namespace that reaches the proxy.
const PROXY_PORT: u16 = 8080;

pub fn available() -> Vec<String> {
    let mut v = vec!["builtin".to_string()];
    if cfg!(target_os = "linux")
        && std::path::Path::new(&format!("{IMAGE_ROOT}/usr/bin/codex")).exists()
    {
        v.push(format!("codex {CODEX_VERSION}"));
    }
    v
}

pub fn supports(agent: &str, provider: Provider) -> anyhow::Result<()> {
    match agent {
        "builtin" => Ok(()),
        "codex" => {
            anyhow::ensure!(
                available().iter().any(|a| a.starts_with("codex")),
                "this server does not have the codex harness"
            );
            anyhow::ensure!(
                matches!(provider, Provider::Openai | Provider::Openrouter),
                "codex needs an OpenAI-compatible provider (openai or openrouter)"
            );
            Ok(())
        }
        other => anyhow::bail!("unknown agent {other:?} (builtin, codex)"),
    }
}

pub fn codex_prompt(
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
pub async fn run_codex(
    net: crate::net::Net,
    run_id: &str,
    bundle: &Arc<Bundle>,
    provider: Provider,
    model: &str,
    api_key: &str,
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
            net, run_id, bundle, provider, model, api_key, prompt, format, timeout, progress,
        );
        return fail("the codex harness needs a Linux enclave".into());
    }
    #[cfg(target_os = "linux")]
    {
        let p2 = progress.clone();
        let scratch = format!("/jails/{run_id}");
        let _ = std::fs::create_dir_all(&scratch);
        let socket = format!("{scratch}/proxy.sock");
        let proxy = match ModelProxy::start(
            net,
            provider,
            model.to_string(),
            api_key.to_string(),
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
            json!({"type": "harness", "content": format!("Preparing the repository for codex {CODEX_VERSION} ({} files)...", bundle.info.file_count)}),
        ]);
        if let Err(e) = crate::jail::materialize(bundle, &repo).await {
            crate::jail::unmount(&repo);
            return fail(format!("preparing the repository: {e:#}"));
        }
        let provider_cfg = format!(
            "model_providers.attest={{ name = \"attest\", base_url = \"http://127.0.0.1:{PROXY_PORT}/v1\", env_key = \"ATTEST_PROXY_TOKEN\", wire_api = \"responses\" }}"
        );
        let spec = crate::jail::Spec {
            repo: repo.clone(),
            image_root: IMAGE_ROOT.into(),
            scratch: scratch.clone(),
            argv: vec![
                "/usr/bin/codex".into(),
                "exec".into(),
                "--skip-git-repo-check".into(),
                "--dangerously-bypass-approvals-and-sandbox".into(),
                "--color".into(),
                "never".into(),
                "-m".into(),
                model.into(),
                "-c".into(),
                "model_provider=\"attest\"".into(),
                "-c".into(),
                provider_cfg,
                "-c".into(),
                "check_for_update_on_startup=false".into(),
                "--output-last-message".into(),
                "/work/last-message.txt".into(),
                prompt,
            ],
            env: vec![
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("HOME".into(), "/work".into()),
                ("CODEX_HOME".into(), "/work/.codex".into()),
                ("TMPDIR".into(), "/tmp".into()),
                ("ATTEST_PROXY_TOKEN".into(), proxy.token.clone()),
                ("NO_COLOR".into(), "1".into()),
                ("TERM".into(), "dumb".into()),
            ],
            cwd: "/repo".into(),
            work_mib: 20,
            collect: vec!["verdict.json".into(), "last-message.txt".into()],
            proxy_socket: socket.clone(),
            proxy_port: PROXY_PORT,
        };
        let started = std::time::SystemTime::now() - Duration::from_secs(1);
        let out = run_jailed(&spec, timeout, progress.clone()).await;
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
                    (Err(why), 0) => (
                        None,
                        Outcome::Error {
                            message: format!("codex did not produce a valid verdict: {why}"),
                        },
                    ),
                    (Err(_), c) => (
                        None,
                        Outcome::Error {
                            message: format!("codex exited with status {c}"),
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

/// Run the jail executor, streaming its log into the trace.
#[cfg(target_os = "linux")]
async fn run_jailed(
    spec: &crate::jail::Spec,
    timeout: Duration,
    progress: Arc<dyn Fn(Vec<Value>) + Send + Sync>,
) -> Result<(i32, BTreeMap<String, String>), String> {
    use tokio::io::{AsyncBufReadExt, BufReader};
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
        let mut lines = BufReader::new(stderr).lines();
        let mut budget = 400_000usize;
        let mut batch = Vec::new();
        while let Ok(Some(l)) = lines.next_line().await {
            if budget == 0 {
                continue;
            }
            let l: String = l.chars().take(4000).collect();
            budget = budget.saturating_sub(l.len());
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
    let mut stdout = BufReader::new(child.stdout.take().unwrap()).lines();
    let read_out = async {
        let mut result = None;
        while let Ok(Some(l)) = stdout.next_line().await {
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
        // Kill first; the jail's processes die with it (parent-death signal).
        let _ = child.kill().await;
    }
    let _ = tokio::time::timeout(Duration::from_secs(10), log_task).await;
    match r {
        Err(_) => Err(format!(
            "codex did not finish within {} minutes",
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
