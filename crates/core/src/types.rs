//! Types shared by the enclave and the CLI.
//!
//! There are no long-term party keys. A party is whoever holds a session
//! link; the parties are expected to know each other and exchange links over
//! a channel they trust. The only signing key is the enclave's, generated at
//! boot and bound to its attestation document.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const DOMAIN_CERTIFICATE: &str = "attest/certificate/v2";
pub const SOURCE_REPO: &str = "https://github.com/sophiawisdom/attest";

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

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Auditee,
    Auditor,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Auditee => "auditee",
            Role::Auditor => "auditor",
        }
    }
    pub fn other(&self) -> Role {
        match self {
            Role::Auditee => Role::Auditor,
            Role::Auditor => Role::Auditee,
        }
    }
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

// ---------------------------------------------------------------- enclave identity

/// Everything the enclave commits to at boot. Its SHA-256 is the Nitro
/// attestation document's `user_data`; the ed25519 key is its `public_key`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EnclaveInfo {
    pub service: String,
    pub version: String,
    /// Source repository and commit this image was built from. Self-reported;
    /// what makes it true is that PCR0 matches a reproducible build of it.
    pub source_repo: String,
    pub source_commit: String,
    /// "nitro" or "dev". Dev enclaves carry no security claim at all.
    pub mode: String,
    pub boot_id: String,
    pub booted_at_ms: u64,
    pub signing_public_key: String,
    /// sha256 of the DER SubjectPublicKeyInfo of the TLS key the enclave
    /// serves with. The key never leaves the enclave, so a TLS connection
    /// whose peer has this SPKI terminates inside this enclave. None in dev.
    pub tls_spki_sha256: Option<String>,
    /// Host name the operator configured (informational).
    pub domain: Option<String>,
    pub harness: HarnessInfo,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HarnessInfo {
    pub version: String,
    pub system_prompt_sha256: String,
    pub tools: Vec<String>,
    pub max_steps_cap: u32,
    /// Inference endpoints per provider. Fixed in the image.
    pub endpoints: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AttestationResponse {
    pub enclave_info_json: String,
    /// Fresh document over the caller's nonce (or the boot document if no
    /// nonce was given). None in dev mode.
    pub document_b64: Option<String>,
}

// ---------------------------------------------------------------- certificate

/// What a finished run produces. The auditee always gets it; the auditor
/// gets it only if the auditee releases the run.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Certificate {
    pub enclave_info_json: String,
    /// Attestation document produced at boot, so the certificate can be
    /// checked offline, later.
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
#[serde(rename_all = "snake_case")]
pub enum Answer {
    Yes,
    No,
    Inconclusive,
    /// The agent wants the auditor to rephrase or narrow the question.
    NeedsClarification,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Verdict {
    pub answer: Answer,
    pub confidence: f64,
    /// Written by the agent for the auditor.
    pub summary: String,
    /// With `needs_clarification`: what the auditor should change.
    pub clarification_request: Option<String>,
}

/// Everything the enclave discloses about how a verdict was produced. It
/// enforces the harness; everything else is what the parties chose, recorded
/// so the other side can weigh it.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Manifest {
    pub schema: String,
    pub session_id: String,
    pub run_id: String,
    /// 1-based position of this run within the session.
    pub run_number: u32,
    /// For follow-up runs: the run whose conversation this continues.
    pub parent_run_id: Option<String>,
    pub boot_id: String,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
    pub question: QuestionRecord,
    /// Messages the auditor sent the agent in this run's conversation
    /// (including ones inherited from parent runs).
    pub auditor_messages: Vec<MessageRecord>,
    pub affidavit: AffidavitRecord,
    pub code: CodeInfo,
    pub model: ModelInfo,
    pub harness: HarnessInfo,
    pub activity: Activity,
    pub instruction_scan: InstructionScan,
    pub history: History,
    pub outcome: Outcome,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct QuestionRecord {
    pub version: u32,
    pub text: String,
    pub text_sha256: String,
    pub max_steps: u32,
    pub allow_fine_tuned: bool,
    pub asked_at_ms: u64,
    pub accepted_at_ms: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MessageRecord {
    pub sent_at_ms: u64,
    pub blinded: bool,
    pub text_sha256: String,
    /// Present only for messages that were not blinded. The auditor can
    /// check a blinded message against its hash.
    pub text: Option<String>,
}

/// Confirmed by the holder of the auditee link.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AffidavitRecord {
    pub organization: String,
    pub repo_url: Option<String>,
    pub git_commit: Option<String>,
    pub statement: String,
    pub confirmed_at_ms: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CodeInfo {
    pub tree_sha256: String,
    pub file_count: u64,
    pub text_file_count: u64,
    pub total_bytes: u64,
    pub uploaded_at_ms: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ModelInfo {
    pub provider: Provider,
    pub endpoint: String,
    pub requested_model: String,
    pub fine_tuned: bool,
    /// Who proposed this model and key.
    pub proposed_by: Role,
    pub approved_at_ms: u64,
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
    /// sha256 tree hash over every file the agent read (path and content
    /// hash), so the auditee can later prove exactly which files were read.
    pub files_read_commitment: String,
    pub grep_calls: u32,
    pub find_calls: u32,
    pub list_calls: u32,
    pub read_calls: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct InstructionScan {
    pub patterns_version: String,
    pub whole_bundle: ScanCounts,
    pub files_read: ScanCounts,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ScanCounts {
    pub files_with_matches: u64,
    pub matches_by_category: BTreeMap<String, u64>,
}

/// What happened before this run.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct History {
    pub prior_runs_in_session: u32,
    pub prior_question_versions: u32,
    /// Distinct code tree hashes earlier runs in this session used. More
    /// than one means the code changed between attempts.
    pub prior_code_trees_in_session: Vec<String>,
    /// Runs of identical question text in other sessions on this enclave
    /// boot (a cheap probe-from-another-session signal).
    pub same_question_text_other_sessions: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Outcome {
    Completed,
    StepLimit,
    Error { message: String },
}
