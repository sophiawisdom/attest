//! One audit run: the agent loop over the bundle, then the manifest.

use crate::bundle::{tool_schemas, Bundle, Tools};
use crate::llm::{self, fit_context, Client, Turn};
use attest_core::harness::{self, MAX_STEPS_CAP, SYSTEM_PROMPT};
use attest_core::*;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

/// Roughly 150k tokens of conversation.
const CONTEXT_BUDGET_CHARS: usize = 600_000;
const MAX_NUDGES: u32 = 3;

pub struct RunInput {
    pub run_id: String,
    pub boot_id: String,
    pub harness: HarnessInfo,
    pub submitted_at_ms: u64,
    pub question: Signed,
    pub question_body: QuestionBody,
    pub affidavit: Signed,
    pub bundle: Bundle,
    pub client: Client,
    pub history: History,
}

pub async fn execute(input: RunInput, steps: Arc<AtomicU32>) -> (CertificateBody, Vec<Value>) {
    let started_at_ms = now_ms();
    let b = &input.bundle;
    let schemas = tool_schemas();
    let mut tools = Tools::new(b);
    let mut trace: Vec<Value> = vec![
        json!({"type": "system", "content": SYSTEM_PROMPT}),
    ];
    let user = harness::user_prompt(&input.question_body.text, b.info.file_count, b.info.total_bytes);
    trace.push(json!({"type": "user", "content": user}));
    let mut turns = vec![Turn::User(user)];

    let max_steps = input.question_body.policy.max_steps.clamp(1, MAX_STEPS_CAP);
    let mut activity = Activity::default();
    let mut response_models = BTreeSet::new();
    let mut upstream = BTreeSet::new();
    let mut key_owner: Option<String> = None;
    let mut verdict: Option<Verdict> = None;
    let mut outcome = Outcome::StepLimit;
    let mut nudges = 0;

    for _ in 0..max_steps {
        fit_context(&mut turns, CONTEXT_BUDGET_CHARS);
        let reply = match input.client.complete(SYSTEM_PROMPT, &turns, &schemas).await {
            Ok(r) => r,
            Err(e) => {
                let msg = format!("{e:#}");
                trace.push(json!({"type": "error", "content": msg}));
                // The manifest gets only the first line: provider error bodies
                // can echo request content.
                let short: String = msg.lines().next().unwrap_or("").chars().take(200).collect();
                outcome = Outcome::Error { message: short };
                break;
            }
        };
        steps.fetch_add(1, Ordering::Relaxed);
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
        trace.push(json!({
            "type": "assistant",
            "text": reply.text,
            "tool_calls": reply.calls.iter().map(|c| json!({"id": c.id, "name": c.name, "args": c.args})).collect::<Vec<_>>(),
            "model": reply.model,
        }));

        turns.push(Turn::Assistant { raw: reply.raw_message.clone() });
        if reply.calls.is_empty() {
            nudges += 1;
            if nudges > MAX_NUDGES {
                outcome = Outcome::Error { message: "model stopped without submitting a verdict".into() };
                break;
            }
            let nudge = "Continue investigating with the tools. When you are done, call submit_verdict.";
            trace.push(json!({"type": "harness", "content": nudge}));
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
                tools.call(&call.name, &call.args)
            };
            trace.push(json!({"type": "tool_result", "id": call.id, "name": call.name, "content": out}));
            results.push((call.id.clone(), out));
        }
        if verdict.is_some() {
            outcome = Outcome::Completed;
            break;
        }
        turns.push(Turn::ToolResults(results));
    }

    activity.files_read = tools.files_read.len() as u64;
    activity.files_read_commitment = tree::files_commitment(tools.files_read.iter());
    activity.list_calls = tools.counts.list;
    activity.find_calls = tools.counts.find;
    activity.read_calls = tools.counts.read;
    activity.grep_calls = tools.counts.grep;

    let instruction_scan = InstructionScan {
        patterns_version: scan::PATTERNS_VERSION.into(),
        whole_bundle: b.scan_all(),
        files_read: b.scan_paths(tools.files_read.keys()),
    };
    let provider = input.client.provider;
    let manifest = Manifest {
        schema: "attest/manifest/v1".into(),
        run_id: input.run_id.clone(),
        boot_id: input.boot_id.clone(),
        submitted_at_ms: input.submitted_at_ms,
        started_at_ms,
        finished_at_ms: now_ms(),
        question_id: input.question.id(),
        question_text_sha256: sha256_hex(input.question_body.text.as_bytes()),
        question: input.question.clone(),
        auditee_public_key: input.affidavit.public_key.clone(),
        affidavit: input.affidavit.clone(),
        code: b.info.clone(),
        model: ModelInfo {
            provider,
            endpoint: llm::endpoint(provider).0.to_string(),
            requested_model: input.client.model.clone(),
            fine_tuned: llm::is_fine_tuned(provider, &input.client.model),
            response_models: response_models.into_iter().collect(),
            key_owner,
            upstream_providers: upstream.into_iter().collect(),
            openrouter_zdr: (provider == Provider::Openrouter).then_some(input.client.openrouter_zdr),
        },
        harness: input.harness.clone(),
        activity,
        instruction_scan,
        history: input.history.clone(),
        outcome,
    };
    trace.push(json!({"type": "files_read", "paths": tools.files_read.keys().collect::<Vec<_>>()}));
    (CertificateBody { manifest, verdict }, trace)
}

fn parse_verdict(args: &Value) -> anyhow::Result<Verdict> {
    let answer = match args["answer"].as_str() {
        Some("yes") => Answer::Yes,
        Some("no") => Answer::No,
        Some("inconclusive") => Answer::Inconclusive,
        other => anyhow::bail!("answer must be yes, no or inconclusive (got {other:?})"),
    };
    let confidence = args["confidence"].as_f64().unwrap_or(0.0).clamp(0.0, 1.0);
    let summary: String = args["summary"].as_str().unwrap_or_default().chars().take(20_000).collect();
    anyhow::ensure!(!summary.trim().is_empty(), "summary is required");
    Ok(Verdict { answer, confidence, summary })
}
