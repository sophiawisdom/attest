use attest_core::verify::VerifiedCertificate;
use attest_core::*;

fn ts(ms: u64) -> String {
    // Seconds since epoch is unambiguous; avoid a date dependency.
    format!("{}s", ms / 1000)
}

pub fn print(v: &VerifiedCertificate) {
    let m = &v.body.manifest;
    println!("== certificate verified");
    match &v.enclave.doc {
        Some(d) => println!("enclave       Nitro, PCR0 {}", d.pcr_hex(0)),
        None => println!("enclave       DEV MODE (nothing attested)"),
    }
    println!("boot / run    {} / {}", m.boot_id, m.run_id);
    println!("question      {}", v.question.text.replace('\n', "\n              "));
    println!("question id   {}", m.question_id);
    println!("auditee       {} ({})", v.affidavit.organization, m.auditee_public_key);
    println!("repo          {} @ {}", v.affidavit.repo_url.as_deref().unwrap_or("-"), v.affidavit.git_commit.as_deref().unwrap_or("-"));
    println!("code          {} files, {} bytes, tree {}", m.code.file_count, m.code.total_bytes, m.code.tree_sha256);
    println!(
        "model         {} via {} (reported: {}; key org: {})",
        m.model.requested_model,
        m.model.endpoint,
        if m.model.response_models.is_empty() { "-".into() } else { m.model.response_models.join(", ") },
        m.model.key_owner.as_deref().unwrap_or("not reported")
    );
    println!(
        "activity      {} model calls, {} tool calls, {} files read, {}+{} tokens",
        m.activity.llm_calls, m.activity.tool_calls, m.activity.files_read, m.activity.input_tokens, m.activity.output_tokens
    );
    println!(
        "history       {} earlier run(s) of this question text this boot, {} by this auditee",
        m.history.prior_runs_same_question_text, m.history.prior_runs_same_auditee
    );
    println!(
        "instr. text   whole bundle: {} file(s) {:?}; files read: {} file(s) {:?}",
        m.instruction_scan.whole_bundle.files_with_matches,
        m.instruction_scan.whole_bundle.matches_by_category,
        m.instruction_scan.files_read.files_with_matches,
        m.instruction_scan.files_read.matches_by_category
    );
    println!("timing        submitted {} finished {}", ts(m.submitted_at_ms), ts(m.finished_at_ms));
    println!("outcome       {:?}", m.outcome);
    match &v.body.verdict {
        Some(vd) => {
            println!("\n== verdict: {:?} (confidence {:.2})", vd.answer, vd.confidence);
            println!("{}", vd.summary);
        }
        None => println!("\n== no verdict"),
    }
    let warns: Vec<&String> = v.enclave.warnings.iter().chain(v.warnings.iter()).collect();
    if !warns.is_empty() {
        println!("\n== for the auditor to weigh");
        for w in warns {
            println!("- {w}");
        }
    }
}

pub fn print_log(b: &RunLogBody) {
    println!("enclave boot {} (booted {}); log is per boot and resets on restart", b.boot_id, ts(b.booted_at_ms));
    if b.entries.is_empty() {
        println!("no runs");
        return;
    }
    println!("{} run(s):", b.entries.len());
    for e in &b.entries {
        println!(
            "  {}  {:<8} {}  {}/{}  code {}  auditee {}  question {}",
            e.run_id,
            format!("{:?}", e.status).to_lowercase(),
            ts(e.submitted_at_ms),
            e.provider.as_str(),
            e.model,
            &e.code_tree_sha256[..16],
            &e.auditee_public_key[..16],
            &e.question_id[..16],
        );
    }
    println!("Every completed run here has a certificate. Ask the auditee for each one they have not released.");
}

pub fn transcript_markdown(trace: &[serde_json::Value]) -> String {
    let mut s = String::from("# Audit transcript (auditee only)\n\n");
    for e in trace {
        match e["type"].as_str().unwrap_or("") {
            "system" => s.push_str(&format!("## System prompt\n\n{}\n\n", e["content"].as_str().unwrap_or(""))),
            "user" => s.push_str(&format!("## Task\n\n{}\n\n", e["content"].as_str().unwrap_or(""))),
            "assistant" => {
                s.push_str("## Model\n\n");
                if let Some(t) = e["text"].as_str().filter(|t| !t.is_empty()) {
                    s.push_str(&format!("{t}\n\n"));
                }
                for c in e["tool_calls"].as_array().into_iter().flatten() {
                    s.push_str(&format!("→ `{}` `{}`\n\n", c["name"].as_str().unwrap_or(""), c["args"]));
                }
            }
            "tool_result" => {
                let c = e["content"].as_str().unwrap_or("");
                s.push_str(&format!("<details><summary>{} result ({} chars)</summary>\n\n```\n{}\n```\n</details>\n\n", e["name"].as_str().unwrap_or(""), c.len(), c));
            }
            "harness" => s.push_str(&format!("_harness: {}_\n\n", e["content"].as_str().unwrap_or(""))),
            "error" => s.push_str(&format!("**error:** {}\n\n", e["content"].as_str().unwrap_or(""))),
            "files_read" => s.push_str(&format!("## Files read\n\n{}\n", e["paths"].as_array().into_iter().flatten().filter_map(|p| p.as_str()).map(|p| format!("- {p}\n")).collect::<String>())),
            _ => {}
        }
    }
    s
}
