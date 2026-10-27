//! Wire and certificate types shared by the enclave, host and CLI.
//!
//! Anything signed is carried as a `Signed` envelope holding the exact JSON
//! bytes that were signed, so verifiers never re-serialize before checking.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const DOMAIN_QUESTION: &str = "attest/question/v1";
pub const DOMAIN_AFFIDAVIT: &str = "attest/affidavit/v1";
pub const DOMAIN_CERTIFICATE: &str = "attest/certificate/v1";
pub const DOMAIN_RUN_LOG: &str = "attest/run-log/v1";

pub const SUBMISSION_MAGIC: &[u8] = b"ATTEST-SUBMISSION-1\n";

/// Detached ed25519 signature over `domain || "\n" || body`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Signed {
    pub domain: String,
    /// Exact JSON bytes that were signed.
    pub body: String,
    /// Hex ed25519 public key of the signer.
    pub public_key: String,
    /// Hex ed25519 signature.
    pub signature: String,
}

// ---------------------------------------------------------------- auditor side

/// What the auditor asks. Signed by the auditor's key.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct QuestionBody {
    pub text: String,
    /// Random, so two auditors asking the same text get different ids.
    pub nonce: String,
    pub created_at_ms: u64,
    pub policy: QuestionPolicy,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct QuestionPolicy {
    /// Accept fine-tuned model ids (e.g. OpenAI `ft:...`). A fine-tune under
    /// the auditee's own account is the cheapest way to get a model that
    /// answers one question wrongly, so the default is to refuse them.
    pub allow_fine_tuned: bool,
    /// Upper bound on model calls for the run (the enclave also has a cap).
    pub max_steps: u32,
}

// ---------------------------------------------------------------- auditee side

/// The auditee's sworn statement about the code bundle. Signed by the
/// auditee's key; the enclave checks the tree hash against the bundle.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AffidavitBody {
    pub statement: String,
    pub organization: String,
    pub question_id: String,
    pub code_tree_sha256: String,
    pub repo_url: Option<String>,
    pub git_commit: Option<String>,
    pub signed_at_ms: u64,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Openai,
    Anthropic,
    Openrouter,
    /// Local OpenAI-compatible server. Only accepted by dev-mode enclaves.
    Mock,
}

impl Provider {
    pub fn as_str(&self) -> &'static str {
        match self {
            Provider::Openai => "openai",
            Provider::Anthropic => "anthropic",
            Provider::Openrouter => "openrouter",
            Provider::Mock => "mock",
        }
    }
}

impl std::str::FromStr for Provider {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> anyhow::Result<Self> {
        Ok(match s {
            "openai" => Provider::Openai,
            "anthropic" => Provider::Anthropic,
            "openrouter" => Provider::Openrouter,
            "mock" => Provider::Mock,
            _ => anyhow::bail!("unknown provider {s:?} (openai, anthropic, openrouter)"),
        })
    }
}

/// Plaintext header of a submission. The whole submission
/// (`SUBMISSION_MAGIC || u64le(header_len) || header_json || tar`) is
/// age-encrypted to the enclave's attested recipient.
#[derive(Serialize, Deserialize, Clone)]
pub struct SubmissionHeader {
    pub question: Signed,
    pub affidavit: Signed,
    pub provider: Provider,
    pub model: String,
    /// The auditee's own inference key. Never leaves the enclave except to
    /// the provider endpoint, and never appears in any output.
    pub api_key: String,
    /// age recipient the result (certificate + full trace) is encrypted to.
    pub reply_recipient: String,
    /// OpenRouter only: ask OpenRouter to route to zero-data-retention endpoints.
    #[serde(default)]
    pub openrouter_zdr: bool,
    /// Mock provider only (dev): host:port of the local OpenAI-compatible server.
    #[serde(default)]
    pub mock_endpoint: Option<String>,
}

// ---------------------------------------------------------------- enclave side

/// Everything the enclave commits to at boot. Its SHA-256 is the Nitro
/// attestation document's `user_data`; the ed25519 key is its `public_key`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EnclaveInfo {
    pub service: String,
    pub version: String,
    /// "nitro" or "dev". Dev enclaves carry no security claim at all.
    pub mode: String,
    pub boot_id: String,
    pub booted_at_ms: u64,
    pub signing_public_key: String,
    pub age_recipient: String,
    pub harness: HarnessInfo,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HarnessInfo {
    pub version: String,
    pub system_prompt_sha256: String,
    pub tools: Vec<String>,
    pub max_steps_cap: u32,
    /// Hostnames the enclave will send inference requests to, per provider.
    pub endpoints: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AttestationResponse {
    pub enclave_info_json: String,
    /// Attestation document produced at boot (no nonce). Embedded in
    /// certificates so they can be checked later, offline.
    pub boot_document_b64: Option<String>,
    /// Fresh document over the caller's nonce, when one was given.
    pub fresh_document_b64: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SubmitResponse {
    pub run_id: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RunStatus {
    Queued,
    Running,
    Done,
    Failed,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RunStatusResponse {
    pub run_id: String,
    pub status: RunStatus,
    pub steps: u32,
    /// age ciphertext (to the submission's reply recipient) of `RunResult`.
    pub result_age_b64: Option<String>,
}

/// Decrypted by the auditee only.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RunResult {
    pub certificate: Certificate,
    pub trace: Vec<serde_json::Value>,
}

/// What the auditee may hand to the auditor.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Certificate {
    pub enclave_info_json: String,
    pub boot_document_b64: Option<String>,
    /// DOMAIN_CERTIFICATE, signed by the enclave key; body is `CertificateBody`.
    pub signed: Signed,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CertificateBody {
    pub manifest: Manifest,
    pub verdict: Option<Verdict>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Answer {
    Yes,
    No,
    Inconclusive,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Verdict {
    pub answer: Answer,
    pub confidence: f64,
    /// Written by the model for the auditor. The auditee reads it before
    /// deciding whether to release.
    pub summary: String,
}

/// Everything the enclave discloses about how the verdict was produced.
/// It enforces almost nothing beyond the harness itself; the point is that
/// the auditor can see what the auditee chose and price it in.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Manifest {
    pub schema: String,
    pub run_id: String,
    pub boot_id: String,
    pub submitted_at_ms: u64,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
    pub question: Signed,
    pub question_id: String,
    pub question_text_sha256: String,
    pub affidavit: Signed,
    pub auditee_public_key: String,
    pub code: CodeInfo,
    pub model: ModelInfo,
    pub harness: HarnessInfo,
    pub activity: Activity,
    pub instruction_scan: InstructionScan,
    pub history: History,
    pub outcome: Outcome,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CodeInfo {
    pub tree_sha256: String,
    pub file_count: u64,
    pub text_file_count: u64,
    pub total_bytes: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ModelInfo {
    pub provider: Provider,
    pub endpoint: String,
    pub requested_model: String,
    pub fine_tuned: bool,
    /// Distinct `model` values the provider reported in its responses.
    pub response_models: Vec<String>,
    /// Organization the API key belongs to, from provider response headers
    /// (`openai-organization`, `anthropic-organization-id`), when present.
    pub key_owner: Option<String>,
    /// OpenRouter only: upstream providers that actually served the calls.
    pub upstream_providers: Vec<String>,
    pub openrouter_zdr: Option<bool>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Activity {
    pub llm_calls: u32,
    pub tool_calls: u32,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub files_read: u64,
    /// sha256 over sorted `path \0 sha256(content) \n` for every file the
    /// model read. Lets the auditee later prove exactly which files were read
    /// without disclosing them now.
    pub files_read_commitment: String,
    pub grep_calls: u32,
    pub find_calls: u32,
    pub list_calls: u32,
    pub read_calls: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct InstructionScan {
    pub patterns_version: String,
    /// Over every text file in the bundle.
    pub whole_bundle: ScanCounts,
    /// Over files the model actually read (all of each file, not just the
    /// lines it requested).
    pub files_read: ScanCounts,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ScanCounts {
    pub files_with_matches: u64,
    pub matches_by_category: BTreeMap<String, u64>,
}

/// Runs seen by this enclave instance (since `boot_id`) before this one.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct History {
    pub prior_runs_same_question_text: u64,
    pub prior_runs_same_question_id: u64,
    pub prior_runs_same_auditee: u64,
    /// Distinct code tree hashes submitted earlier against the same question
    /// text. More than one means the code changed between attempts.
    pub prior_code_hashes_same_question_text: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Outcome {
    Completed,
    StepLimit,
    Error { message: String },
}

// ---------------------------------------------------------------- run log

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RunLogEntry {
    pub run_id: String,
    pub submitted_at_ms: u64,
    pub question_id: String,
    pub question_text_sha256: String,
    pub auditee_public_key: String,
    pub code_tree_sha256: String,
    pub provider: Provider,
    pub model: String,
    pub status: RunStatus,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RunLogBody {
    pub boot_id: String,
    pub booted_at_ms: u64,
    pub generated_at_ms: u64,
    pub query: RunLogQuery,
    pub entries: Vec<RunLogEntry>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RunLogQuery {
    pub question_text_sha256: Option<String>,
    pub auditee_public_key: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RunLogResponse {
    pub enclave_info_json: String,
    pub boot_document_b64: Option<String>,
    pub signed: Signed,
}
