//! The agent loop: a model with read-only tools over the bundle.

use crate::bundle::{tool_schemas, Bundle, Tools};
use crate::llm::{fit_context, Client, Turn};
use attest_core::harness::{MAX_STEPS_CAP, SYSTEM_PROMPT};
use attest_core::*;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Roughly 150k tokens of conversation.
const CONTEXT_BUDGET_CHARS: usize = 600_000;
const MAX_TOOL_CALLS_PER_TURN: usize = 16;
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
    /// The run's connections, with how many requests went through each.
    pub connections: Vec<ConnectionRecord>,
}

/// Run until the model submits a verdict, errors, or hits `max_steps`.
/// `progress` receives trace entries as they happen (auditee-visible).
pub async fn agent_loop(
    client: &Client,
    bundle: &std::sync::Arc<Bundle>,
    has_code: bool,
    connections: Vec<crate::connections::Connection>,
    net: &crate::net::Net,
    sandbox: Option<std::sync::Arc<crate::sandbox::Sandbox>>,
    mut turns: Vec<Turn>,
    max_steps: u32,
    format: &AnswerFormat,
    progress: &(dyn Fn(Vec<Value>) + Send + Sync),
    gate: Option<&crate::approvals::Gate>,
) -> AgentOutput {
    let owned = tool_schemas(format, has_code, crate::connections::agent_tools(&connections));
    let schemas: Vec<(&str, &str, Value)> = owned.iter().map(|(a, b, c)| (a.as_str(), b.as_str(), c.clone())).collect();
    let mut tools = Tools::new(bundle, sandbox);
    let mut conns: Vec<(crate::connections::Connection, crate::net::Net)> =
        connections.into_iter().map(|c| { let n = c.net(net); (c, n) }).collect();
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
                // The manifest gets no error text: provider error bodies can
                // echo request content. The auditee's trace has the detail.
                outcome = Outcome::Error {
                    message: "a model request failed (details are in the auditee's trace)".into(),
                };
                break;
            }
        };
        activity.llm_calls += 1;
        activity.input_tokens = activity.input_tokens.saturating_add(reply.input_tokens);
        activity.output_tokens = activity.output_tokens.saturating_add(reply.output_tokens);
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
        turns.push(Turn::Assistant {
            raw: reply.raw_message.clone(),
        });

        if reply.calls.is_empty() {
            nudges += 1;
            if nudges > MAX_NUDGES {
                progress(events);
                outcome = Outcome::Error {
                    message: "the model stopped without submitting a verdict".into(),
                };
                break;
            }
            let nudge =
                "Continue investigating with the tools. When you are done, call submit_verdict.";
            events.push(json!({"type": "harness", "content": nudge}));
            progress(events);
            turns.push(Turn::User(nudge.into()));
            continue;
        }

        let mut results = Vec::new();
        for (i, call) in reply.calls.iter().enumerate() {
            activity.tool_calls += 1;
            // Each call still gets a result (the APIs require one), but only
            // the first few run: with each output capped, this bounds what
            // one turn adds to the conversation and how long it takes.
            let out = if i >= MAX_TOOL_CALLS_PER_TURN {
                format!("error: at most {MAX_TOOL_CALLS_PER_TURN} tool calls run per turn; this one was skipped, call it again")
            } else if call.name == "submit_verdict" {
                match parse_verdict(&call.args, format) {
                    Ok(v) => {
                        verdict = Some(v);
                        "verdict recorded".to_string()
                    }
                    Err(e) => format!("error: {e}"),
                }
            } else if let Some(_) = match gate {
                Some(g) => Some(g.ask(&call.name, &call.args, Some(&call.id)).await).filter(|d| !d.approve),
                None => None,
            } {
                // A fixed text: the auditee's reason stays in its own trace,
                // so it can't steer the agent unseen by the auditor.
                crate::approvals::DENIED.to_string()
            } else if let Some(out) = crate::connections::dispatch(&mut conns, &call.name, &call.args).await {
                out
            } else if !has_code {
                format!("error: there is no tool named {:?}; use only the tools you were given", call.name)
            } else {
                tools.call(&call.name, &call.args).await
            };
            events.push(
                json!({"type": "tool_result", "id": call.id, "name": call.name, "content": out}),
            );
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
    progress(vec![
        json!({"type": "files_read", "paths": files_read.keys().collect::<Vec<_>>()}),
    ]);
    AgentOutput {
        turns,
        verdict,
        outcome,
        activity,
        files_read,
        response_models: response_models.into_iter().collect(),
        upstream_providers: upstream.into_iter().collect(),
        key_owner,
        connections: conns.into_iter().map(|(c, _)| c.rec).collect(),
    }
}

pub fn parse_verdict(args: &Value, format: &AnswerFormat) -> anyhow::Result<Verdict> {
    if let AnswerFormat::Choice { .. } = format {
        let v = Verdict {
            answer: Answer::Inconclusive,
            summary: String::new(),
            clarification_request: None,
            choice: args["choice"].as_str().map(String::from),
        };
        return format.enforce(v).map_err(|e| anyhow::anyhow!(e));
    }
    let answer = match args["answer"].as_str() {
        Some("yes") => Answer::Yes,
        Some("no") => Answer::No,
        Some("inconclusive") => Answer::Inconclusive,
        Some("answered") => Answer::Answered,
        Some("needs_clarification") => Answer::NeedsClarification,
        other => anyhow::bail!(
            "answer must be yes, no, answered, inconclusive or needs_clarification (got {other:?})"
        ),
    };
    // Any `confidence` the model sends is dropped.
    let summary: String = args["summary"].as_str().unwrap_or_default().to_string();
    anyhow::ensure!(
        format.is_strict() || !summary.trim().is_empty(),
        "summary is required"
    );
    let clarification_request: Option<String> = args["clarification_request"]
        .as_str()
        .map(|s| s.chars().take(5_000).collect::<String>())
        .filter(|s| !s.trim().is_empty());
    if answer == Answer::NeedsClarification && clarification_request.is_none() {
        anyhow::bail!("needs_clarification requires clarification_request");
    }
    format
        .enforce(Verdict {
            answer,
            summary,
            clarification_request,
            choice: None,
        })
        .map_err(|e| anyhow::anyhow!(e))
}
