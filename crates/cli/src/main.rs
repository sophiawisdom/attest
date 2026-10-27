//! attest CLI.
//!
//! Auditor:  keygen, question, log, verify
//! Auditee:  keygen, submit, fetch
//! Both:     ui (local web app)

mod bundle;
mod ops;
mod report;
mod ui;

use anyhow::{anyhow, bail, Context, Result};
use attest_core::nitro::ExpectedPcrs;
use attest_core::verify::{EnclavePolicy, VerifiedEnclave};
use attest_core::*;
use clap::{Args, Parser, Subcommand};
use ops::{read_json, write_json};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Parser)]
#[command(name = "attest", about = "Attested LLM code audits: the auditee keeps the code, the auditor gets a signed verdict")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args, Clone)]
struct PolicyArgs {
    /// Expected enclave measurements (nitro-cli build output).
    #[arg(long)]
    pcrs: Option<PathBuf>,
    /// Accept a dev-mode enclave (proves nothing; for testing).
    #[arg(long)]
    allow_dev: bool,
    /// Accept any genuine Nitro enclave without checking which build it runs.
    #[arg(long)]
    skip_measurement: bool,
}

impl PolicyArgs {
    fn policy(&self) -> Result<EnclavePolicy> {
        let expected = match &self.pcrs {
            Some(p) => Some(ExpectedPcrs::from_json(&std::fs::read_to_string(p)?)?),
            None => None,
        };
        Ok(EnclavePolicy { expected, allow_dev: self.allow_dev, skip_measurement: self.skip_measurement })
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a signing key (and an age key for receiving results).
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Auditor: write and sign a question.
    Question {
        #[arg(long)]
        key: PathBuf,
        #[arg(long, conflicts_with = "text_file")]
        text: Option<String>,
        #[arg(long)]
        text_file: Option<PathBuf>,
        #[arg(long)]
        allow_fine_tuned: bool,
        #[arg(long, default_value_t = 150)]
        max_steps: u32,
        #[arg(long)]
        out: PathBuf,
    },
    /// Check an enclave's attestation and print what it commits to.
    Info {
        #[arg(long)]
        enclave: String,
        #[command(flatten)]
        policy: PolicyArgs,
    },
    /// Auditee: sign the affidavit, encrypt the code to the enclave, and start a run.
    Submit {
        #[arg(long)]
        enclave: String,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        question: PathBuf,
        /// Repository to audit. In a git checkout, only tracked files are sent.
        #[arg(long)]
        dir: PathBuf,
        /// Organization making the affidavit.
        #[arg(long)]
        org: String,
        /// openai | anthropic | openrouter
        #[arg(long)]
        provider: Provider,
        #[arg(long)]
        model: String,
        /// Environment variable holding the API key.
        #[arg(long, default_value = "ATTEST_API_KEY")]
        api_key_env: String,
        /// Defaults to `git remote get-url origin`.
        #[arg(long)]
        repo_url: Option<String>,
        /// Defaults to `git rev-parse HEAD`.
        #[arg(long)]
        git_commit: Option<String>,
        /// Allow uncommitted changes to tracked files (the affidavit's commit claim would then be false).
        #[arg(long)]
        allow_dirty: bool,
        /// OpenRouter: route only to zero-data-retention endpoints.
        #[arg(long)]
        zdr: bool,
        /// Dev only: host:port of a local OpenAI-compatible server (with --provider mock).
        #[arg(long)]
        mock_endpoint: Option<String>,
        /// Do not ask for confirmation before signing.
        #[arg(long)]
        yes: bool,
        /// Wait for the run and fetch the result.
        #[arg(long)]
        wait: bool,
        /// Where `--wait` writes results.
        #[arg(long, default_value = "attest-runs")]
        out_dir: PathBuf,
        #[command(flatten)]
        policy: PolicyArgs,
    },
    /// Auditee: wait for a run, decrypt the result, write certificate and transcript.
    Fetch {
        #[arg(long)]
        enclave: String,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        run: String,
        #[arg(long, default_value = "attest-runs")]
        out_dir: PathBuf,
        #[command(flatten)]
        policy: PolicyArgs,
    },
    /// Auditor: verify a released certificate.
    Verify {
        #[arg(long)]
        certificate: PathBuf,
        /// The question you issued; the certificate must answer exactly it.
        #[arg(long)]
        question: Option<PathBuf>,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        policy: PolicyArgs,
    },
    /// Auditor: list every run of your question's text on the enclave (since its boot).
    Log {
        #[arg(long)]
        enclave: String,
        #[arg(long, conflicts_with = "auditee")]
        question: Option<PathBuf>,
        /// Hex public key of an auditee.
        #[arg(long)]
        auditee: Option<String>,
        #[command(flatten)]
        policy: PolicyArgs,
    },
    /// Local web app for auditors and auditees.
    Ui {
        /// Where keys, questions, runs and certificates are kept.
        #[arg(long, default_value = "attest-workspace")]
        workspace: PathBuf,
        #[arg(long, default_value_t = 7717)]
        port: u16,
        /// Enclave URL to start with (can be changed in the app).
        #[arg(long)]
        enclave: Option<String>,
        /// Open the browser.
        #[arg(long)]
        open: bool,
    },
}

fn warn_all(ws: &[String]) {
    for w in ws {
        eprintln!("warning: {w}");
    }
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Keygen { out } => {
            let kf = ops::generate_key(&out)?;
            println!("wrote {} (public key {})", out.display(), kf.public_key);
        }

        Cmd::Question { key, text, text_file, allow_fine_tuned, max_steps, out } => {
            let keys = ops::load_key(&key)?;
            let text = match (text, text_file) {
                (Some(t), _) => t,
                (None, Some(f)) => std::fs::read_to_string(f)?,
                (None, None) => bail!("give --text or --text-file"),
            };
            let signed = ops::make_question(&keys, &text, allow_fine_tuned, max_steps)?;
            let body: QuestionBody = signed.open(DOMAIN_QUESTION)?;
            write_json(&out, &signed)?;
            println!("question id {}", signed.id());
            println!("text sha256 {}", sha256_hex(body.text.as_bytes()));
            println!("wrote {}; send it to the auditee", out.display());
        }

        Cmd::Info { enclave, policy } => {
            let v = ops::attest_enclave(&enclave, &policy.policy()?)?;
            warn_all(&v.warnings);
            if let Some(d) = &v.doc {
                println!("verified Nitro enclave, PCR0 {}", d.pcr_hex(0));
            }
            println!("{}", serde_json::to_string_pretty(&v.info)?);
        }

        Cmd::Submit {
            enclave, key, question, dir, org, provider, model, api_key_env, repo_url, git_commit,
            allow_dirty, zdr, mock_endpoint, yes, wait, out_dir, policy,
        } => {
            let policy = policy.policy()?;
            let keys = ops::load_key(&key)?;
            let question: Signed = read_json(&question)?;
            let qbody: QuestionBody = question.open(DOMAIN_QUESTION).context("question signature")?;
            let api_key = std::env::var(&api_key_env).map_err(|_| anyhow!("set {api_key_env} to your API key"))?;

            let prepared = ops::prepare(&dir)?;
            if prepared.git.dirty && !allow_dirty {
                bail!("{} has uncommitted changes to tracked files; commit them or pass --allow-dirty", dir.display());
            }
            let repo_url = repo_url.or(prepared.git.remote.clone());
            let git_commit = git_commit.or(prepared.git.head.clone());

            let enclave_v = ops::attest_enclave(&enclave, &policy)?;
            warn_all(&enclave_v.warnings);

            let statement = ops::affidavit_statement(&org, &prepared.tree, repo_url.as_deref(), git_commit.as_deref());
            eprintln!("\nQuestion ({}):\n  {}\n", question.id(), qbody.text.replace('\n', "\n  "));
            eprintln!("Code: {} files, {} bytes, tree {}", prepared.file_count, prepared.total_bytes, prepared.tree);
            eprintln!("Model: {} {} (the auditor will see this, and the API key's organization)", provider.as_str(), model);
            eprintln!("Enclave: {} boot {}\n", enclave_v.info.mode, enclave_v.info.boot_id);
            eprintln!("Affidavit:\n  {statement}\n");
            if !yes {
                eprint!("Sign the affidavit and submit? Type 'yes': ");
                let mut s = String::new();
                std::io::stdin().read_line(&mut s)?;
                if s.trim() != "yes" {
                    bail!("aborted");
                }
            }
            let run_id = ops::submit(ops::SubmitArgs {
                enclave: &enclave,
                enclave_v: &enclave_v,
                keys: &keys,
                question: &question,
                prepared,
                org,
                provider,
                model,
                api_key,
                repo_url,
                git_commit,
                zdr,
                mock_endpoint,
            })?;
            println!("run {run_id}");
            if wait {
                fetch(&enclave, &keys, &run_id, &out_dir, &enclave_v, &policy)?;
            } else {
                println!("fetch with: attest fetch --enclave {enclave} --key {} --run {run_id}", key.display());
            }
        }

        Cmd::Fetch { enclave, key, run, out_dir, policy } => {
            let policy = policy.policy()?;
            let v = ops::attest_enclave(&enclave, &policy)?;
            warn_all(&v.warnings);
            fetch(&enclave, &ops::load_key(&key)?, &run, &out_dir, &v, &policy)?;
        }

        Cmd::Verify { certificate, question, json, policy } => {
            let cert: Certificate = read_json(&certificate)?;
            let q: Option<Signed> = question.as_deref().map(read_json).transpose()?;
            if q.is_none() {
                eprintln!("note: no --question given, so this only shows the certificate answers *some* question");
            }
            let v = ops::verify(&cert, &policy.policy()?, q.as_ref())?;
            if json {
                println!("{}", serde_json::to_string_pretty(&v.body)?);
            } else {
                report::print(&v);
            }
        }

        Cmd::Log { enclave, question, auditee, policy } => {
            let policy = policy.policy()?;
            let q: Option<Signed> = question.as_deref().map(read_json).transpose()?;
            let query = match (&q, &auditee) {
                (Some(s), _) => ops::LogQuery::Question(s),
                (None, Some(a)) => ops::LogQuery::Auditee(a),
                _ => bail!("give --question or --auditee"),
            };
            let (v, body) = ops::fetch_log(&enclave, &policy, query)?;
            warn_all(&v.warnings);
            report::print_log(&body);
        }

        Cmd::Ui { workspace, port, enclave, open } => ui::run(workspace, port, enclave, open)?,
    }
    Ok(())
}

fn fetch(enclave: &str, keys: &ops::Keys, run: &str, out_dir: &Path, enclave_v: &VerifiedEnclave, policy: &EnclavePolicy) -> Result<()> {
    let mut last = u32::MAX;
    let status = loop {
        let s = ops::poll(enclave, run)?;
        if s.result_age_b64.is_some() {
            break s;
        }
        if s.status == RunStatus::Failed {
            bail!("run failed before producing a result");
        }
        if s.steps != last {
            eprintln!("  {:?}: {} model calls", s.status, s.steps);
            last = s.steps;
        }
        std::thread::sleep(Duration::from_secs(3));
    };
    let result = ops::open_result(&status, keys, Some(&serde_json::to_string(&enclave_v.info)?))?;

    let dir = out_dir.join(run);
    std::fs::create_dir_all(&dir)?;
    write_json(&dir.join("certificate.json"), &result.certificate)?;
    write_json(&dir.join("trace.json"), &result.trace)?;
    std::fs::write(dir.join("transcript.md"), report::transcript_markdown(&result.trace))?;

    let v = ops::verify(&result.certificate, policy, None)?;
    report::print(&v);
    println!("\nwrote {}/{{certificate.json, trace.json, transcript.md}}", dir.display());
    println!("Only certificate.json is meant for the auditor. Read transcript.md and the summary above before releasing it.");
    Ok(())
}
