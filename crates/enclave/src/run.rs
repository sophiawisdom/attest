//! The agent loop: a model with read-only tools over the bundle.

use crate::bundle::{tool_schemas, Bundle, Tools};
use crate::llm::{fit_context, Client, Turn};
use attest_core::harness::{MAX_STEPS_CAP, SYSTEM_PROMPT};
use attest_core::*;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Roughly 150k tokens of conversation.
const CONTEXT_BUDGET_CHARS: usize = 600_000;
const MAX_NUDGES: u32 = 3;

pub struct AgentOutput {
    /// Full conversation, for continuing with a follow-up later.
    pub turns: Vec<Turn>,
    pub verdict: Option<Verdict>,
    pub outcome: Outcome,
    pub activity: Activity,
    pub files_read: BTreeMap<String, [u8; 32]>,
    pub response_models: Vec<String>,
    pub upstream_providers: Vec<String>,
    pub key_owner: Option<String>,
}

/// Run until the model submits a verdict, errors, or hits `max_steps`.
/// `progress` receives trace entries as they happen (auditee-visible).
pub async fn agent_loop(
    client: &Client,
    bundle: &std::sync::Arc<Bundle>,
    sandbox: Option<std::sync::Arc<crate::sandbox::Sandbox>>,
    mut turns: Vec<Turn>,
    max_steps: u32,
    progress: &(dyn Fn(Vec<Value>) + Send + Sync),
) -> AgentOutput {
    let schemas = tool_schemas();
    let mut tools = Tools::new(bundle, sandbox);
    let mut activity = Activity::default();
    let mut response_models = BTreeSet::new();
    let mut upstream = BTreeSet::new();
    let mut key_owner: Option<String> = None;
    let mut verdict: Option<Verdict> = None;
    let mut outcome = Outcome::StepLimit;
    let mut nudges = 0;

    for _ in 0..max_steps.clamp(1, MAX_STEPS_CAP) {
        fit_context(&mut turns, CONTEXT_BUDGET_CHARS);
        let reply = match client.complete(SYSTEM_PROMPT, &turns, &schemas).await {
            Ok(r) => r,
            Err(e) => {
                let msg = format!("{e:#}");
                progress(vec![json!({"type": "error", "content": msg})]);
                // Only the first line goes in the manifest: provider error
                // bodies can echo request content.
                let short: String = msg.lines().next().unwrap_or("").chars().take(300).collect();
                outcome = Outcome::Error { message: short };
                break;
            }
        };
        activity.llm_calls += 1;
        activity.input_tokens += reply.input_tokens;
        activity.output_tokens += reply.output_tokens;
        if let Some(m) = &reply.model {
            response_models.insert(m.clone());
        }
        if let Some(p) = &reply.upstream_provider {
            upstream.insert(p.clone());
        }
        if key_owner.is_none() {
            key_owner = reply.key_owner.clone();
        }
        let mut events = vec![json!({
            "type": "assistant",
            "text": reply.text,
            "tool_calls": reply.calls.iter().map(|c| json!({"id": c.id, "name": c.name, "args": c.args})).collect::<Vec<_>>(),
            "model": reply.model,
        })];
        turns.push(Turn::Assistant { raw: reply.raw_message.clone() });

        if reply.calls.is_empty() {
            nudges += 1;
            if nudges > MAX_NUDGES {
                progress(events);
                outcome = Outcome::Error { message: "the model stopped without submitting a verdict".into() };
                break;
            }
            let nudge = "Continue investigating with the tools. When you are done, call submit_verdict.";
            events.push(json!({"type": "harness", "content": nudge}));
            progress(events);
            turns.push(Turn::User(nudge.into()));
            continue;
        }

        let mut results = Vec::new();
        for call in &reply.calls {
            activity.tool_calls += 1;
            let out = if call.name == "submit_verdict" {
                match parse_verdict(&call.args) {
                    Ok(v) => {
                        verdict = Some(v);
                        "verdict recorded".to_string()
                    }
                    Err(e) => format!("error: {e}"),
                }
            } else {
                tools.call(&call.name, &call.args).await
            };
            events.push(json!({"type": "tool_result", "id": call.id, "name": call.name, "content": out}));
            results.push((call.id.clone(), out));
        }
        progress(events);
        // Keep the tool results in the conversation even when finishing, so a
        // follow-up can continue from a well-formed state.
        turns.push(Turn::ToolResults(results));
        if verdict.is_some() {
            outcome = Outcome::Completed;
            break;
        }
    }

    activity.files_read = tools.files_read.len() as u64;
    activity.files_read_commitment = tree::files_commitment(tools.files_read.iter());
    activity.list_calls = tools.counts.list;
    activity.find_calls = tools.counts.find;
    activity.read_calls = tools.counts.read;
    activity.grep_calls = tools.counts.grep;
    activity.python_calls = tools.counts.python;
    let files_read = tools.files_read.clone();
    progress(vec![json!({"type": "files_read", "paths": files_read.keys().collect::<Vec<_>>()})]);
    AgentOutput {
        turns,
        verdict,
        outcome,
        activity,
        files_read,
        response_models: response_models.into_iter().collect(),
        upstream_providers: upstream.into_iter().collect(),
        key_owner,
    }
}

fn parse_verdict(args: &Value) -> anyhow::Result<Verdict> {
    let answer = match args["answer"].as_str() {
        Some("yes") => Answer::Yes,
        Some("no") => Answer::No,
        Some("inconclusive") => Answer::Inconclusive,
        Some("needs_clarification") => Answer::NeedsClarification,
        other => anyhow::bail!("answer must be yes, no, inconclusive or needs_clarification (got {other:?})"),
    };
    let confidence = args["confidence"].as_f64().unwrap_or(0.0).clamp(0.0, 1.0);
    let summary: String = args["summary"].as_str().unwrap_or_default().chars().take(20_000).collect();
    anyhow::ensure!(!summary.trim().is_empty(), "summary is required");
    let clarification_request: Option<String> = args["clarification_request"]
        .as_str()
        .map(|s| s.chars().take(5_000).collect::<String>())
        .filter(|s| !s.trim().is_empty());
    if answer == Answer::NeedsClarification && clarification_request.is_none() {
        anyhow::bail!("needs_clarification requires clarification_request");
    }
    Ok(Verdict { answer, confidence, summary, clarification_request })
}
