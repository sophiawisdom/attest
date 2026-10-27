//! Verifier side: check that an enclave (or a certificate it signed) is the
//! measured build, and turn a certificate into a human-readable report.

use crate::nitro::{self, AttestationDoc, ExpectedPcrs};
use crate::types::*;
use anyhow::{anyhow, bail, Result};
use base64::Engine;

#[derive(Debug, Clone, Default)]
pub struct EnclavePolicy {
    pub expected: Option<ExpectedPcrs>,
    /// Accept dev-mode enclaves, which prove nothing.
    pub allow_dev: bool,
    /// Accept a genuine Nitro enclave without checking which build it runs.
    pub skip_measurement: bool,
}

#[derive(Debug, Clone)]
pub struct VerifiedEnclave {
    pub info: EnclaveInfo,
    pub doc: Option<AttestationDoc>,
    pub warnings: Vec<String>,
}

/// Check `doc_b64` attests to exactly `info_json` and its signing key.
/// When `nonce` is given the document must carry it.
pub fn verify_enclave(
    info_json: &str,
    doc_b64: Option<&str>,
    nonce: Option<&[u8]>,
    policy: &EnclavePolicy,
) -> Result<VerifiedEnclave> {
    let info: EnclaveInfo = serde_json::from_str(info_json)?;
    let mut warnings = Vec::new();
    if info.service != "attest" {
        bail!("not an attest enclave (service = {:?})", info.service);
    }
    match info.mode.as_str() {
        "dev" => {
            if !policy.allow_dev {
                bail!("enclave is in dev mode: nothing is attested (dev-mode enclaves are only accepted when explicitly allowed)");
            }
            warnings.push("DEV MODE: no hardware attestation. Nothing about this enclave is proven.".into());
            return Ok(VerifiedEnclave { info, doc: None, warnings });
        }
        "nitro" => {}
        m => bail!("unknown enclave mode {m:?}"),
    }
    let doc_b64 = doc_b64.ok_or_else(|| anyhow!("nitro enclave but no attestation document"))?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(doc_b64)?;
    let doc = nitro::verify_document(&bytes)?;

    let user_data = doc.user_data.as_ref().ok_or_else(|| anyhow!("attestation document has no user_data"))?;
    if user_data.as_ref() != crate::sha256(info_json.as_bytes()).as_slice() {
        bail!("attestation document does not commit to this enclave info");
    }
    let pk = doc.public_key.as_ref().ok_or_else(|| anyhow!("attestation document has no public_key"))?;
    if hex::encode(pk.as_ref()) != info.signing_public_key.to_ascii_lowercase() {
        bail!("attestation document public_key is not the enclave signing key");
    }
    if let Some(n) = nonce {
        if doc.nonce.as_ref().map(|x| x.as_ref()) != Some(n) {
            bail!("attestation document does not carry our nonce (replayed?)");
        }
    }
    let zero = |i| doc.pcr_hex(i).chars().all(|c| c == '0');
    if zero(0) && zero(1) && zero(2) {
        bail!("PCR0-2 are zero: enclave is running in debug mode, its memory is readable by the host");
    }
    if info.harness.system_prompt_sha256 != crate::harness::system_prompt_sha256() {
        warnings.push(format!(
            "enclave harness prompt {} differs from this verifier's {} (different version?)",
            info.harness.system_prompt_sha256,
            crate::harness::system_prompt_sha256()
        ));
    }
    match &policy.expected {
        Some(e) => e.check(&doc)?,
        None if policy.skip_measurement => warnings.push(
            "MEASUREMENT NOT CHECKED: this is a genuine Nitro enclave, but it could be running any code.".into(),
        ),
        None => bail!(
            "no expected measurements given: a genuine enclave running arbitrary code would pass. \
             Provide pcrs.json from a reproducible build, or explicitly accept any Nitro enclave"
        ),
    }
    Ok(VerifiedEnclave { info, doc: Some(doc), warnings })
}

pub struct VerifiedCertificate {
    pub enclave: VerifiedEnclave,
    pub body: CertificateBody,
    pub question: QuestionBody,
    pub affidavit: AffidavitBody,
    pub warnings: Vec<String>,
}

/// Verify a certificate end to end. If `expected_question` is given, the
/// certificate must be for exactly that signed question.
pub fn verify_certificate(
    cert: &Certificate,
    policy: &EnclavePolicy,
    expected_question: Option<&Signed>,
) -> Result<VerifiedCertificate> {
    let enclave = verify_enclave(&cert.enclave_info_json, cert.boot_document_b64.as_deref(), None, policy)?;
    let body: CertificateBody = cert.signed.open_by(DOMAIN_CERTIFICATE, &enclave.info.signing_public_key)?;
    let m = &body.manifest;
    if m.boot_id != enclave.info.boot_id {
        bail!("manifest boot id does not match the enclave that signed it");
    }
    let question: QuestionBody = m.question.open(DOMAIN_QUESTION)?;
    if m.question.id() != m.question_id {
        bail!("manifest question id mismatch");
    }
    if crate::sha256_hex(question.text.as_bytes()) != m.question_text_sha256 {
        bail!("manifest question text hash mismatch");
    }
    let affidavit: AffidavitBody = m.affidavit.open(DOMAIN_AFFIDAVIT)?;
    if m.affidavit.public_key != m.auditee_public_key {
        bail!("affidavit signer is not the recorded auditee");
    }
    if affidavit.code_tree_sha256 != m.code.tree_sha256 || affidavit.question_id != m.question_id {
        bail!("affidavit does not bind this code and question");
    }
    if let Some(q) = expected_question {
        if q.id() != m.question_id {
            bail!("certificate answers a different question than the one you issued");
        }
    }
    let warnings = manifest_warnings(m, &question, &affidavit);
    Ok(VerifiedCertificate { enclave, body, question, affidavit, warnings })
}

/// Things in the manifest an auditor should weigh. None of them make the
/// certificate invalid; they are what the auditee chose.
pub fn manifest_warnings(m: &Manifest, q: &QuestionBody, a: &AffidavitBody) -> Vec<String> {
    let mut w = Vec::new();
    if m.outcome != Outcome::Completed {
        w.push(format!("run did not complete normally: {:?}", m.outcome));
    }
    if m.model.fine_tuned {
        w.push(format!("model {} is a fine-tune (policy allowed it)", m.model.requested_model));
    }
    let org = a.organization.to_ascii_lowercase();
    let provider_org = match m.model.provider {
        Provider::Openai => Some("openai"),
        Provider::Anthropic => Some("anthropic"),
        _ => None,
    };
    if let Some(p) = provider_org {
        if org.contains(p) {
            w.push(format!(
                "self-hosted inference: the auditee ({}) operates the model endpoint ({}), so it controls what model actually answered",
                a.organization, m.model.endpoint
            ));
        }
    }
    if m.model.provider == Provider::Openrouter {
        w.push(format!(
            "routed through OpenRouter (zdr={:?}); upstream providers: {}",
            m.model.openrouter_zdr,
            if m.model.upstream_providers.is_empty() { "unreported".into() } else { m.model.upstream_providers.join(", ") }
        ));
    }
    if m.model.response_models.iter().any(|r| !r.starts_with(&m.model.requested_model) && !m.model.requested_model.starts_with(r.as_str())) {
        w.push(format!(
            "provider reported model(s) {:?} for requested {}",
            m.model.response_models, m.model.requested_model
        ));
    }
    let h = &m.history;
    if h.prior_runs_same_question_text > 0 {
        w.push(format!(
            "{} earlier run(s) of this question text on this enclave boot; ask the auditee for those certificates",
            h.prior_runs_same_question_text
        ));
    }
    if h.prior_code_hashes_same_question_text.iter().any(|c| c != &m.code.tree_sha256) {
        w.push(format!(
            "the code changed between attempts: {} distinct earlier tree hash(es)",
            h.prior_code_hashes_same_question_text.iter().filter(|c| *c != &m.code.tree_sha256).count()
        ));
    }
    let s = &m.instruction_scan.files_read;
    if s.files_with_matches > 0 {
        w.push(format!(
            "{} file(s) the model read contain instruction-like text ({})",
            s.files_with_matches,
            s.matches_by_category.iter().map(|(k, n)| format!("{} ×{n}", k.replace('_', " "))).collect::<Vec<_>>().join(", ")
        ));
    }
    if m.activity.files_read == 0 {
        w.push("the model read no files".into());
    }
    if a.git_commit.is_none() {
        w.push("affidavit names no git commit".into());
    }
    if q.policy.allow_fine_tuned {
        w.push("your question allowed fine-tuned models".into());
    }
    w
}
