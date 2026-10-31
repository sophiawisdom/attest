//! Tool-call approval: with it on, the auditee (or an agent acting for it)
//! approves or denies each tool call the audit agent makes, before it runs.
//!
//! The built-in agent asks before each call. Jailed harnesses ask from a
//! pre-tool hook (Claude Code, Codex) or an extension (pi) that calls the
//! run's model proxy; as a backstop the proxy withholds from the model the
//! result of any call that wasn't decided, so a harness that skips its
//! hook (or a hook that fails open) still shows the model nothing.

use anyhow::{bail, Result};
use attest_core::now_ms;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// How long a call waits for a decision before it's denied.
pub const DECISION_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// What pending calls show of their input, at most.
const MAX_SHOWN_INPUT: usize = 20_000;
/// Longest call id kept in the ledger; longer ones are denied.
pub const MAX_CALL_ID: usize = 256;
/// Call ids one run's ledger (and withheld set) holds; past it, calls are
/// denied. The jailed agent asks freely, and this memory isn't in its cgroup.
const MAX_LEDGER: usize = 20_000;
/// Harness bookkeeping that reads and changes nothing; approved without asking.
const INTERNAL: &[&str] = &["TodoWrite", "todowrite", "update_plan", "get_goal", "create_goal", "update_goal"];

/// What the agent is told about a denial, always: the auditee's reason is
/// for its own record, never a channel to the agent the auditor can't see.
pub const DENIED: &str = "The auditee denied this call.";

pub const WITHHELD: &str = "[withheld by the enclave: this tool call ran without the auditee's approval, so its result is not shown]";

#[derive(Clone, Debug)]
pub struct Decision {
    pub approve: bool,
    pub reason: String,
}

struct Pending {
    id: u64,
    run_id: String,
    run_number: u32,
    agent: String,
    tool: String,
    input: Value,
    asked_at_ms: u64,
    tx: tokio::sync::oneshot::Sender<Decision>,
}

/// A session's calls waiting for a decision (in memory only: a run that
/// outlives its enclave fails anyway).
#[derive(Default)]
pub struct Queue {
    inner: Mutex<(u64, Vec<Pending>)>,
    notify: tokio::sync::Notify,
}

impl Queue {
    pub fn list(&self) -> Vec<Value> {
        let g = self.inner.lock().unwrap();
        g.1.iter()
            .map(|p| {
                json!({"id": p.id, "run_id": p.run_id, "run_number": p.run_number, "agent": p.agent,
                       "tool": p.tool, "input": p.input, "asked_at_ms": p.asked_at_ms,
                       "deadline_ms": p.asked_at_ms + DECISION_TIMEOUT.as_millis() as u64})
            })
            .collect()
    }

    /// The pending calls, waiting up to `wait` for one if there are none.
    pub async fn wait_list(&self, wait: Duration) -> Vec<Value> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let notified = self.notify.notified();
            let l = self.list();
            if !l.is_empty() || tokio::time::Instant::now() >= deadline {
                return l;
            }
            let _ = tokio::time::timeout_at(deadline, notified).await;
        }
    }

    pub fn decide(&self, id: u64, d: Decision) -> Result<()> {
        let p = {
            let mut g = self.inner.lock().unwrap();
            let Some(i) = g.1.iter().position(|p| p.id == id) else {
                bail!("no pending tool call {id} (it may have been decided, timed out, or its run ended)");
            };
            g.1.remove(i)
        };
        let _ = p.tx.send(d);
        self.notify.notify_waiters();
        Ok(())
    }

    fn add(&self, run_id: &str, run_number: u32, agent: &str, tool: &str, input: Value) -> (u64, tokio::sync::oneshot::Receiver<Decision>) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let id = {
            let mut g = self.inner.lock().unwrap();
            g.0 += 1;
            let id = g.0;
            g.1.push(Pending { id, run_id: run_id.into(), run_number, agent: agent.into(), tool: tool.into(), input, asked_at_ms: now_ms(), tx });
            id
        };
        self.notify.notify_waiters();
        (id, rx)
    }

    /// Drop a finished run's pending calls (their askers are gone).
    pub fn cancel_run(&self, run_id: &str) {
        self.inner.lock().unwrap().1.retain(|p| p.run_id != run_id);
        self.notify.notify_waiters();
    }

    fn remove(&self, id: u64) {
        self.inner.lock().unwrap().1.retain(|p| p.id != id);
        self.notify.notify_waiters();
    }
}

#[derive(Default, Clone, Copy, Debug)]
pub struct Counts {
    pub approved: u32,
    pub denied: u32,
    /// Denied because no decision came in time.
    pub timed_out: u32,
    /// Results the proxy withheld (calls that ran without a decision).
    pub withheld: u32,
}

/// One run's connection to its session's queue.
#[derive(Clone)]
pub struct Gate {
    queue: Arc<Queue>,
    run_id: String,
    run_number: u32,
    agent: String,
    pub counts: Arc<Mutex<Counts>>,
    /// Call ids decided so far, and whether each was approved.
    ledger: Arc<Mutex<HashMap<String, bool>>>,
    withheld_ids: Arc<Mutex<HashSet<String>>>,
    /// Wakes the auditee's view (long polls) when a call is waiting.
    on_change: Arc<dyn Fn() + Send + Sync>,
    progress: Arc<dyn Fn(Vec<Value>) + Send + Sync>,
}

fn shown(input: &Value) -> Value {
    let s = input.to_string();
    if s.len() <= MAX_SHOWN_INPUT {
        return input.clone();
    }
    json!({"truncated": true, "start": s.chars().take(MAX_SHOWN_INPUT).collect::<String>()})
}

impl Gate {
    pub fn new(
        queue: Arc<Queue>,
        run_id: &str,
        run_number: u32,
        agent: &str,
        on_change: Arc<dyn Fn() + Send + Sync>,
        progress: Arc<dyn Fn(Vec<Value>) + Send + Sync>,
    ) -> Gate {
        Gate {
            queue,
            run_id: run_id.into(),
            run_number,
            agent: agent.into(),
            counts: Default::default(),
            ledger: Default::default(),
            withheld_ids: Default::default(),
            on_change,
            progress,
        }
    }

    /// Ask the auditee about one call, waiting for the decision.
    pub async fn ask(&self, tool: &str, input: &Value, call_id: Option<&str>) -> Decision {
        if let Some(cid) = call_id {
            let refuse = if cid.len() > MAX_CALL_ID {
                Some(format!("the tool call id is over {MAX_CALL_ID} bytes"))
            } else if self.ledger.lock().unwrap().len() >= MAX_LEDGER {
                Some(format!("this run has asked about {MAX_LEDGER} tool calls already"))
            } else {
                None
            };
            if let Some(reason) = refuse {
                self.counts.lock().unwrap().denied += 1;
                return Decision { approve: false, reason };
            }
        }
        let d = if INTERNAL.contains(&tool) {
            Decision { approve: true, reason: "harness bookkeeping, approved without asking".into() }
        } else {
            let (id, rx) = self.queue.add(&self.run_id, self.run_number, &self.agent, tool, shown(input));
            (self.on_change)();
            match tokio::time::timeout(DECISION_TIMEOUT, rx).await {
                Ok(Ok(d)) => d,
                _ => {
                    self.queue.remove(id);
                    self.counts.lock().unwrap().timed_out += 1;
                    Decision { approve: false, reason: format!("no decision within {} minutes", DECISION_TIMEOUT.as_secs() / 60) }
                }
            }
        };
        {
            let mut c = self.counts.lock().unwrap();
            if d.approve {
                c.approved += 1;
            } else {
                c.denied += 1;
            }
        }
        if let Some(cid) = call_id {
            let mut l = self.ledger.lock().unwrap();
            l.insert(cid.to_string(), d.approve);
            // pi's OpenAI ids are "call_id|item_id".
            if let Some((a, _)) = cid.split_once('|') {
                l.insert(a.to_string(), d.approve);
            }
        }
        (self.progress)(vec![json!({"type": "approval", "tool": tool, "approved": d.approve, "reason": d.reason})]);
        (self.on_change)();
        d
    }

    fn decided(&self, call_id: &str) -> bool {
        self.ledger.lock().unwrap().contains_key(call_id)
    }

    fn note_withheld(&self, call_id: &str, tool: &str) {
        let mut ids = self.withheld_ids.lock().unwrap();
        if ids.len() < MAX_LEDGER && call_id.len() <= MAX_CALL_ID && ids.insert(call_id.to_string()) {
            drop(ids);
            self.counts.lock().unwrap().withheld += 1;
            (self.progress)(vec![json!({"type": "error", "content": format!("a {tool} call ran without a decision; the enclave withheld its result from the model")})]);
        }
    }

    /// The proxy's backstop: in a model request, replace the result of every
    /// tool call that wasn't decided. Returns the new body if it changed.
    pub fn withhold_undecided(&self, body: &[u8]) -> Option<Vec<u8>> {
        let mut v: Value = serde_json::from_slice(body).ok()?;
        let mut changed = false;
        // Calls in the history, by id: (name, arguments).
        let mut calls: HashMap<String, (String, Value)> = HashMap::new();
        if let Some(items) = v.get("input").and_then(|i| i.as_array()) {
            for it in items {
                if matches!(it["type"].as_str(), Some("function_call") | Some("custom_tool_call")) {
                    if let Some(id) = it["call_id"].as_str() {
                        let args = it["arguments"].as_str().and_then(|a| serde_json::from_str(a).ok()).unwrap_or(Value::Null);
                        calls.insert(id.into(), (it["name"].as_str().unwrap_or("?").into(), args));
                    }
                }
            }
        }
        if let Some(msgs) = v.get("messages").and_then(|m| m.as_array()) {
            for m in msgs {
                for b in m["content"].as_array().into_iter().flatten() {
                    if b["type"] == "tool_use" {
                        if let Some(id) = b["id"].as_str() {
                            calls.insert(id.into(), (b["name"].as_str().unwrap_or("?").into(), b["input"].clone()));
                        }
                    }
                }
                for c in m["tool_calls"].as_array().into_iter().flatten() {
                    if let Some(id) = c["id"].as_str() {
                        calls.insert(id.into(), (c["function"]["name"].as_str().unwrap_or("?").into(), Value::Null));
                    }
                }
            }
        }
        let allowed = |id: &str| -> bool {
            if self.decided(id) {
                return true;
            }
            // Codex polls a running command's output with write_stdin and
            // no input; that adds nothing the approved command didn't.
            matches!(calls.get(id), Some((n, a)) if n == "write_stdin" && a["chars"].as_str().unwrap_or("").is_empty())
        };
        let name_of = |id: &str| calls.get(id).map(|c| c.0.clone()).unwrap_or_else(|| "tool".into());
        // Responses API
        if let Some(items) = v.get_mut("input").and_then(|i| i.as_array_mut()) {
            for it in items.iter_mut() {
                if matches!(it["type"].as_str(), Some("function_call_output") | Some("custom_tool_call_output")) {
                    let id = it["call_id"].as_str().unwrap_or("").to_string();
                    if !allowed(&id) {
                        self.note_withheld(&id, &name_of(&id));
                        it["output"] = json!(WITHHELD);
                        changed = true;
                    }
                }
            }
        }
        // Messages API and Chat Completions
        if let Some(msgs) = v.get_mut("messages").and_then(|m| m.as_array_mut()) {
            for m in msgs.iter_mut() {
                if m["role"] == "tool" {
                    let id = m["tool_call_id"].as_str().unwrap_or("").to_string();
                    if !allowed(&id) {
                        self.note_withheld(&id, &name_of(&id));
                        m["content"] = json!(WITHHELD);
                        changed = true;
                    }
                }
                if let Some(blocks) = m.get_mut("content").and_then(|c| c.as_array_mut()) {
                    for b in blocks.iter_mut() {
                        if b["type"] == "tool_result" {
                            let id = b["tool_use_id"].as_str().unwrap_or("").to_string();
                            if !allowed(&id) {
                                self.note_withheld(&id, &name_of(&id));
                                b["content"] = json!(WITHHELD);
                                changed = true;
                            }
                        }
                    }
                }
            }
        }
        if changed {
            serde_json::to_vec(&v).ok()
        } else {
            None
        }
    }
}

/// The pre-tool hook jailed harnesses run: it sends the call to the run's
/// model proxy and prints the decision in the harness's format. Any error
/// denies (a hook that fails or times out would let the call run).
pub fn hook_script(harness: &str) -> String {
    let ask = r#"const http = require("http");
function ask(call) {
  return new Promise((resolve) => {
    const body = JSON.stringify(call);
    const req = http.request({host: "127.0.0.1", port: PORT, path: "/attest/tool-approval", method: "POST",
      headers: {"content-type": "application/json", "content-length": Buffer.byteLength(body), "authorization": "Bearer " + process.env.ATTEST_PROXY_TOKEN}},
      (res) => { let d = ""; res.on("data", (c) => d += c); res.on("end", () => {
        try { const v = JSON.parse(d); resolve(res.statusCode === 200 ? v : {approve: false, reason: "the enclave refused: " + d.slice(0, 200)}); }
        catch (e) { resolve({approve: false, reason: "no decision: " + e}); } }); });
    req.on("error", (e) => resolve({approve: false, reason: "no decision: " + e}));
    req.end(body);
  });
}
"#;
    let main = if harness == "pi" {
        r#"module.exports = function (pi) {
  pi.on("tool_call", async (event) => {
    const d = await ask({tool: event.toolName, input: event.input, id: event.toolCallId});
    if (!d.approve) return {block: true, reason: "The auditee denied this call."};
  });
};
"#
    } else {
        r#"let input = "";
process.stdin.on("data", (c) => input += c);
process.stdin.on("end", async () => {
  let d;
  try { const h = JSON.parse(input); d = await ask({tool: h.tool_name, input: h.tool_input, id: h.tool_use_id}); }
  catch (e) { d = {approve: false, reason: "no decision: " + e}; }
  process.stdout.write(d.approve ? "{}" : JSON.stringify({hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny",
    permissionDecisionReason: "The auditee denied this call."}}));
});
"#
    };
    format!("{ask}{main}")
}

/// A shell command that runs `hook_script` (inline, so nothing in the
/// agent's writable directories can replace it).
pub fn hook_command(harness: &str, port: u16) -> String {
    use base64::Engine;
    let js = hook_script(harness).replace("PORT", &port.to_string());
    format!("/usr/bin/node -e \"eval(Buffer.from('{}','base64').toString())\"", base64::engine::general_purpose::STANDARD.encode(js))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate() -> Gate {
        Gate::new(Arc::default(), "r1", 1, "codex", Arc::new(|| {}), Arc::new(|_| {}))
    }

    #[tokio::test]
    async fn decisions_and_backstop() {
        let g = gate();
        let q = g.queue.clone();
        let g2 = g.clone();
        let asked = tokio::spawn(async move { g2.ask("Bash", &json!({"command": "cat secrets"}), Some("call_1")).await });
        let pending = q.wait_list(Duration::from_secs(5)).await;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0]["tool"], "Bash");
        q.decide(pending[0]["id"].as_u64().unwrap(), Decision { approve: false, reason: "no".into() }).unwrap();
        assert!(!asked.await.unwrap().approve);
        assert!(g.ask("TodoWrite", &json!({}), Some("call_t")).await.approve);
        // call_1 was decided (denied: the harness reports that itself);
        // call_2 never asked; call_3 polls output with no input.
        let body = json!({"input": [
            {"type": "function_call", "call_id": "call_1", "name": "exec_command", "arguments": "{}"},
            {"type": "function_call_output", "call_id": "call_1", "output": "blocked by hook"},
            {"type": "function_call", "call_id": "call_2", "name": "write_stdin", "arguments": "{\"session_id\":1,\"chars\":\"import os\\n\"}"},
            {"type": "function_call_output", "call_id": "call_2", "output": "secret output"},
            {"type": "function_call", "call_id": "call_3", "name": "write_stdin", "arguments": "{\"session_id\":1,\"chars\":\"\"}"},
            {"type": "function_call_output", "call_id": "call_3", "output": "more output"}
        ]});
        let out: Value = serde_json::from_slice(&g.withhold_undecided(body.to_string().as_bytes()).unwrap()).unwrap();
        assert_eq!(out["input"][1]["output"], "blocked by hook");
        assert_eq!(out["input"][3]["output"], WITHHELD);
        assert_eq!(out["input"][5]["output"], "more output");
        let msgs = json!({"messages": [
            {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_9", "name": "Read", "input": {}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_9", "content": "file text"}]}
        ]});
        let out: Value = serde_json::from_slice(&g.withhold_undecided(msgs.to_string().as_bytes()).unwrap()).unwrap();
        assert_eq!(out["messages"][1]["content"][0]["content"], WITHHELD);
        let c = *g.counts.lock().unwrap();
        assert_eq!((c.approved, c.denied, c.withheld), (1, 1, 2));
        assert!(g.withhold_undecided(json!({"input": []}).to_string().as_bytes()).is_none());
    }

    #[test]
    fn hook_scripts_parse() {
        for h in ["claude-code", "codex", "pi"] {
            let s = hook_script(h).replace("PORT", "8080");
            assert!(s.contains("/attest/tool-approval"));
        }
        assert!(hook_command("codex", 8080).starts_with("/usr/bin/node -e \"eval(Buffer.from('"));
    }
}
