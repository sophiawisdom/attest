//! Operations shared by the CLI and the local web UI.

use crate::bundle;
use anyhow::{anyhow, bail, Context, Result};
use attest_core::verify::{verify_certificate, verify_enclave, EnclavePolicy, VerifiedCertificate, VerifiedEnclave};
use attest_core::*;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::Write;
use std::path::Path;
use std::time::Duration;

// ------------------------------------------------------------------ keys and files

#[derive(Serialize, Deserialize, Clone)]
pub struct KeyFile {
    pub ed25519_seed: String,
    pub public_key: String,
    pub age_identity: String,
    pub age_recipient: String,
}

pub struct Keys {
    pub signing: ed25519_dalek::SigningKey,
    pub age: age::x25519::Identity,
    pub file: KeyFile,
}

pub fn generate_key(path: &Path) -> Result<KeyFile> {
    use age::secrecy::ExposeSecret;
    let sk = sign::generate_signing_key();
    let id = age::x25519::Identity::generate();
    let kf = KeyFile {
        ed25519_seed: hex::encode(sk.to_bytes()),
        public_key: hex::encode(sk.verifying_key().to_bytes()),
        age_identity: id.to_string().expose_secret().to_string(),
        age_recipient: id.to_public().to_string(),
    };
    write_private(path, &(serde_json::to_string_pretty(&kf)? + "\n"))?;
    Ok(kf)
}

pub fn load_key(path: &Path) -> Result<Keys> {
    let file: KeyFile = read_json(path)?;
    let signing = sign::signing_key_from_hex(&file.ed25519_seed)?;
    let age = file.age_identity.parse().map_err(|e| anyhow!("age identity: {e}"))?;
    Ok(Keys { signing, age, file })
}

pub fn write_private(path: &Path, contents: &str) -> Result<()> {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).with_context(|| format!("creating {} (refusing to overwrite)", path.display()))?;
    f.write_all(contents.as_bytes())?;
    Ok(())
}

pub fn write_json<T: Serialize>(path: &Path, v: &T) -> Result<()> {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(v)? + "\n").with_context(|| format!("writing {}", path.display()))
}

pub fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    serde_json::from_str(&std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?)
        .with_context(|| format!("parsing {}", path.display()))
}

// ------------------------------------------------------------------ HTTP

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(1800)))
        .build()
        .into()
}

fn check(mut resp: ureq::http::Response<ureq::Body>) -> Result<Vec<u8>> {
    let status = resp.status().as_u16();
    let body = resp.body_mut().with_config().limit(4 << 30).read_to_vec()?;
    if status != 200 {
        let msg = serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|v| v["error"].as_str().map(String::from))
            .unwrap_or_else(|| String::from_utf8_lossy(&body).into_owned());
        bail!("enclave returned HTTP {status}: {msg}");
    }
    Ok(body)
}

fn get<T: for<'de> Deserialize<'de>>(url: &str) -> Result<T> {
    let resp = agent().get(url).call().with_context(|| format!("could not reach {url}"))?;
    Ok(serde_json::from_slice(&check(resp)?)?)
}

pub fn base(url: &str) -> String {
    url.trim().trim_end_matches('/').to_string()
}

/// Fresh, nonce-bound attestation of the enclave we are about to talk to.
pub fn attest_enclave(enclave: &str, policy: &EnclavePolicy) -> Result<VerifiedEnclave> {
    let nonce: [u8; 32] = rand::random();
    let a: AttestationResponse = get(&format!("{}/v1/attestation?nonce={}", base(enclave), hex::encode(nonce)))?;
    let v = verify_enclave(&a.enclave_info_json, a.fresh_document_b64.as_deref(), Some(&nonce), policy)?;
    // The boot document must also check out, since certificates embed it.
    verify_enclave(&a.enclave_info_json, a.boot_document_b64.as_deref(), None, policy)?;
    Ok(v)
}

pub fn enclave_json(v: &VerifiedEnclave) -> Value {
    json!({
        "mode": v.info.mode,
        "boot_id": v.info.boot_id,
        "booted_at_ms": v.info.booted_at_ms,
        "version": v.info.version,
        "pcr0": v.doc.as_ref().map(|d| d.pcr_hex(0)),
        "harness": v.info.harness,
        "warnings": v.warnings,
    })
}

// ------------------------------------------------------------------ auditor

pub fn make_question(keys: &Keys, text: &str, allow_fine_tuned: bool, max_steps: u32) -> Result<Signed> {
    let text = text.trim();
    if text.is_empty() {
        bail!("the question is empty");
    }
    let nonce: [u8; 16] = rand::random();
    let body = QuestionBody {
        text: text.to_string(),
        nonce: hex::encode(nonce),
        created_at_ms: now_ms(),
        policy: QuestionPolicy { allow_fine_tuned, max_steps },
    };
    sign::sign(&keys.signing, DOMAIN_QUESTION, &body)
}

pub enum LogQuery<'a> {
    Question(&'a Signed),
    Auditee(&'a str),
}

pub fn fetch_log(enclave: &str, policy: &EnclavePolicy, q: LogQuery) -> Result<(VerifiedEnclave, RunLogBody)> {
    let v = attest_enclave(enclave, policy)?;
    let query = match q {
        LogQuery::Question(s) => {
            let b: QuestionBody = s.open(DOMAIN_QUESTION)?;
            format!("question_text_sha256={}", sha256_hex(b.text.as_bytes()))
        }
        LogQuery::Auditee(a) => format!("auditee={a}"),
    };
    let r: RunLogResponse = get(&format!("{}/v1/log?{query}", base(enclave)))?;
    if r.enclave_info_json != serde_json::to_string(&v.info)? {
        bail!("run log was signed by a different enclave boot than the one just attested");
    }
    let body: RunLogBody = r.signed.open_by(DOMAIN_RUN_LOG, &v.info.signing_public_key)?;
    Ok((v, body))
}

// ------------------------------------------------------------------ auditee

pub struct Prepared {
    pub tar: Vec<u8>,
    pub tree: String,
    pub file_count: usize,
    pub total_bytes: u64,
    pub git: bundle::GitInfo,
}

pub fn prepare(dir: &Path) -> Result<Prepared> {
    if !dir.is_dir() {
        bail!("{} is not a directory", dir.display());
    }
    let git = bundle::git_info(dir);
    let files = bundle::collect(dir)?;
    let total_bytes = files.iter().map(|(_, b)| b.len() as u64).sum();
    let (tar, tree) = bundle::tar_and_hash(&files)?;
    Ok(Prepared { tar, tree, file_count: files.len(), total_bytes, git })
}

pub fn affidavit_statement(org: &str, tree: &str, repo_url: Option<&str>, git_commit: Option<&str>) -> String {
    format!(
        "On behalf of {org}, I affirm that the code bundle with tree hash {tree} is a complete and unmodified copy of {} at commit {}, \
         which is the source currently used in production for the systems the question concerns, and that no content in it was added, \
         modified, or arranged with the intent of influencing the outcome of this or any automated audit.",
        repo_url.unwrap_or("(repository not named)"),
        git_commit.unwrap_or("(commit not named)"),
    )
}

pub struct SubmitArgs<'a> {
    pub enclave: &'a str,
    pub enclave_v: &'a VerifiedEnclave,
    pub keys: &'a Keys,
    pub question: &'a Signed,
    pub prepared: Prepared,
    pub org: String,
    pub provider: Provider,
    pub model: String,
    pub api_key: String,
    pub repo_url: Option<String>,
    pub git_commit: Option<String>,
    pub zdr: bool,
    pub mock_endpoint: Option<String>,
}

/// Sign the affidavit, encrypt everything to the attested enclave, upload.
pub fn submit(a: SubmitArgs) -> Result<String> {
    let SubmitArgs { enclave, enclave_v, keys, question, prepared, org, provider, model, api_key, repo_url, git_commit, zdr, mock_endpoint } = a;
    question.open::<QuestionBody>(DOMAIN_QUESTION).context("question signature")?;
    if org.trim().is_empty() {
        bail!("organization is required for the affidavit");
    }
    if model.trim().is_empty() || api_key.trim().is_empty() {
        bail!("model and API key are required");
    }
    let statement = affidavit_statement(&org, &prepared.tree, repo_url.as_deref(), git_commit.as_deref());
    let affidavit = sign::sign(
        &keys.signing,
        DOMAIN_AFFIDAVIT,
        &AffidavitBody {
            statement,
            organization: org,
            question_id: question.id(),
            code_tree_sha256: prepared.tree.clone(),
            repo_url,
            git_commit,
            signed_at_ms: now_ms(),
        },
    )?;
    let header = SubmissionHeader {
        question: question.clone(),
        affidavit,
        provider,
        model,
        api_key,
        reply_recipient: keys.file.age_recipient.clone(),
        openrouter_zdr: zdr,
        mock_endpoint,
    };
    let plain = join_submission(&header, &prepared.tar)?;
    drop(prepared);
    let recipient: age::x25519::Recipient =
        enclave_v.info.age_recipient.parse().map_err(|e| anyhow!("enclave recipient: {e}"))?;
    let ct = age::encrypt(&recipient, &plain)?;
    drop(plain);
    let resp = agent()
        .post(&format!("{}/v1/runs", base(enclave)))
        .header("content-type", "application/octet-stream")
        .send(&ct[..])?;
    let sr: SubmitResponse = serde_json::from_slice(&check(resp)?)?;
    Ok(sr.run_id)
}

pub fn poll(enclave: &str, run: &str) -> Result<RunStatusResponse> {
    get(&format!("{}/v1/runs/{run}", base(enclave)))
}

/// Decrypt a finished run and check it came from the expected enclave boot.
pub fn open_result(status: &RunStatusResponse, keys: &Keys, enclave_info_json: Option<&str>) -> Result<RunResult> {
    let b64 = status.result_age_b64.as_ref().ok_or_else(|| anyhow!("run has no result yet"))?;
    let ct = base64::engine::general_purpose::STANDARD.decode(b64)?;
    let plain = age::decrypt(&keys.age, &ct).map_err(|_| anyhow!("result is not encrypted to this key"))?;
    let result: RunResult = serde_json::from_slice(&plain)?;
    if let Some(info) = enclave_info_json {
        if result.certificate.enclave_info_json != info {
            bail!("result was produced by a different enclave boot");
        }
    }
    Ok(result)
}

// ------------------------------------------------------------------ verification

pub fn verify(cert: &Certificate, policy: &EnclavePolicy, question: Option<&Signed>) -> Result<VerifiedCertificate> {
    verify_certificate(cert, policy, question)
}

/// Verified certificate as JSON for the UI.
pub fn report_json(v: &VerifiedCertificate) -> Value {
    let mut warnings = v.enclave.warnings.clone();
    warnings.extend(v.warnings.iter().cloned());
    json!({
        "enclave": enclave_json(&v.enclave),
        "question": v.question,
        "affidavit": v.affidavit,
        "manifest": v.body.manifest,
        "verdict": v.body.verdict,
        "warnings": warnings,
    })
}
