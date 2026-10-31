//! Verifier side: check that an enclave (or a certificate it signed) is a
//! measured build, and list what a certificate's reader should weigh.

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
            warnings.push(
                "DEV MODE: no hardware attestation. Nothing about this enclave is proven.".into(),
            );
            return Ok(VerifiedEnclave {
                info,
                doc: None,
                warnings,
            });
        }
        "nitro" => {}
        m => bail!("unknown enclave mode {m:?}"),
    }
    let doc_b64 = doc_b64.ok_or_else(|| anyhow!("nitro enclave but no attestation document"))?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(doc_b64)?;
    let doc = nitro::verify_document(&bytes)?;

    let user_data = doc
        .user_data
        .as_ref()
        .ok_or_else(|| anyhow!("attestation document has no user_data"))?;
    if user_data.as_ref() != crate::sha256(info_json.as_bytes()).as_slice() {
        bail!("attestation document does not commit to this enclave info");
    }
    let pk = doc
        .public_key
        .as_ref()
        .ok_or_else(|| anyhow!("attestation document has no public_key"))?;
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
        bail!(
            "PCR0-2 are zero: enclave is running in debug mode, its memory is readable by the host"
        );
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
    Ok(VerifiedEnclave {
        info,
        doc: Some(doc),
        warnings,
    })
}

pub struct VerifiedCertificate {
    pub enclave: VerifiedEnclave,
    pub body: CertificateBody,
    pub warnings: Vec<String>,
}

pub fn verify_certificate(
    cert: &Certificate,
    policy: &EnclavePolicy,
) -> Result<VerifiedCertificate> {
    let enclave = verify_enclave(
        &cert.enclave_info_json,
        cert.boot_document_b64.as_deref(),
        None,
        policy,
    )?;
    let body: CertificateBody = cert
        .signed
        .open_by(DOMAIN_CERTIFICATE, &enclave.info.signing_public_key)?;
    let m = &body.manifest;
    if m.boot_id != enclave.info.boot_id {
        bail!("manifest boot id does not match the enclave that signed it");
    }
    if m.verdict_only() {
        // The commitment stays closed: no tree or salt to check it against.
        if !m.code.tree_sha256.is_empty() || !m.code.commitment_salt.is_empty() {
            bail!("a verdict-only certificate must not open the code commitment");
        }
    } else if m.code.commitment_sha256 != code_commitment(&m.code.commitment_salt, &m.code.tree_sha256) {
        bail!("the code commitment shown before release does not open to this tree");
    }
    if crate::sha256_hex(m.question.text.as_bytes()) != m.question.text_sha256 {
        bail!("manifest question text hash mismatch");
    }
    for msg in &m.auditor_messages {
        if let Some(t) = &msg.text {
            if crate::sha256_hex(t.as_bytes()) != msg.text_sha256 {
                bail!("manifest auditor message hash mismatch");
            }
        }
    }
    let warnings = manifest_warnings(m);
    Ok(VerifiedCertificate {
        enclave,
        body,
        warnings,
    })
}

pub struct VerifiedDisclosure {
    pub enclave: VerifiedEnclave,
    pub body: DisclosureBody,
}

pub fn verify_disclosure(d: &Disclosure, policy: &EnclavePolicy) -> Result<VerifiedDisclosure> {
    let enclave = verify_enclave(
        &d.enclave_info_json,
        d.boot_document_b64.as_deref(),
        None,
        policy,
    )?;
    let body: DisclosureBody = d
        .signed
        .open_by(DOMAIN_DISCLOSURE, &enclave.info.signing_public_key)?;
    if body.boot_id != enclave.info.boot_id {
        bail!("disclosure boot id does not match the enclave that signed it");
    }
    match &body.content {
        DisclosureContent::File {
            sha256,
            text,
            base64: b64,
            size,
            ..
        } => {
            let bytes = match (text, b64) {
                (Some(t), None) => t.as_bytes().to_vec(),
                (None, Some(b)) => base64::engine::general_purpose::STANDARD.decode(b)?,
                _ => bail!("file disclosure must carry exactly one of text and base64"),
            };
            if crate::sha256_hex(&bytes) != *sha256 || bytes.len() as u64 != *size {
                bail!("disclosed file content does not match its hash");
            }
        }
        DisclosureContent::Python {
            code, code_sha256, ..
        } => {
            if crate::sha256_hex(code.as_bytes()) != *code_sha256 {
                bail!("disclosed script does not match its hash");
            }
        }
    }
    Ok(VerifiedDisclosure { enclave, body })
}

fn categories(c: &ScanCounts) -> String {
    c.matches_by_category
        .iter()
        .map(|(k, n)| format!("{} ×{n}", k.replace('_', " ")))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Things a certificate's reader should weigh. None make it invalid; they
/// are what the parties chose or what happened.
pub fn manifest_warnings(m: &Manifest) -> Vec<String> {
    let mut w = Vec::new();
    if let Some(b) = &m.ran_on_boot_id {
        w.push(format!(
            "the run happened on boot {b}; a successor enclave of the same image took its sessions over and signed this"
        ));
    }
    match &m.outcome {
        Outcome::Completed => {}
        Outcome::StepLimit => w.push("the agent hit its step limit before answering".into()),
        Outcome::Error { message } => w.push(format!("the run failed: {message}")),
    }
    if m.model.provider == Provider::Azure {
        w.push(format!(
            "Azure deployment \"{}\" may be a fine-tuned model (Azure doesn't show which to the key); the question allowed fine-tunes. The model Azure reported was {}",
            m.model.requested_model,
            if m.model.response_models.is_empty() { "not given".into() } else { m.model.response_models.join(", ") }
        ));
    } else if m.model.fine_tuned {
        w.push(format!(
            "model {} is a fine-tune (the question allowed it)",
            m.model.requested_model
        ));
    }
    let org = m.affidavit.organization.to_ascii_lowercase();
    let provider_org = match m.model.provider {
        Provider::Openai => Some("openai"),
        Provider::Anthropic => Some("anthropic"),
        _ => None,
    };
    if let Some(p) = provider_org {
        if org.contains(p) {
            w.push(format!(
                "self-hosted inference: the auditee ({}) operates the model endpoint ({}), so it controls which model actually answered",
                m.affidavit.organization, m.model.endpoint
            ));
        }
    }
    if m.model.response_models.iter().any(|r| {
        !r.starts_with(&m.model.requested_model) && !m.model.requested_model.starts_with(r.as_str())
    }) {
        w.push(format!(
            "provider reported model(s) {} for requested {}",
            m.model.response_models.join(", "),
            m.model.requested_model
        ));
    }
    let h = &m.history;
    let other_trees = h
        .prior_code_trees_in_session
        .iter()
        .filter(|c| *c != &m.code.tree_sha256)
        .count()
        .max(h.distinct_prior_code_trees as usize);
    if other_trees > 0 {
        w.push(format!("the code changed between runs: {other_trees} other version(s) were used earlier in this session"));
    }
    if h.same_question_text_other_sessions > 0 {
        w.push(format!(
            "the same question text was run in {} other session(s) on this enclave",
            h.same_question_text_other_sessions
        ));
    }
    let s = &m.instruction_scan.files_read;
    if s.files_with_matches > 0 {
        w.push(format!(
            "{} file(s) the agent read contain instruction-like text ({})",
            s.files_with_matches,
            categories(s)
        ));
    }
    if m.has_code && m.activity.files_read == 0 && !m.verdict_only() {
        w.push("the agent read no files".into());
    }
    for c in &m.connections {
        if c.kind == "mcp" {
            w.push(format!("the agent could call {} tool(s) of an MCP server the auditee chose, {} ({}): {}; the enclave knows only its address", c.tools.len(), c.name, c.hosts.join(", "), c.tools.join(", ")));
            continue;
        }
        match &c.identity {
            Some(i) => w.push(format!("the agent could reach {} ({}), whose data the auditee controls; the service identified the account as {i}", c.name, c.hosts.join(", "))),
            None => w.push(format!("the agent could reach {} ({}), an API the auditee chose; the enclave knows only its host name", c.name, c.hosts.join(", "))),
        }
    }
    if m.has_code && m.affidavit.git_commit.is_none() {
        w.push("the code's repository and commit are not recorded".into());
    } else if m.has_code && !m.affidavit.fetched_by_enclave {
        w.push("the code was uploaded: its repository and commit are the auditee's word, not checked by the enclave".into());
    }
    if let Some(a) = &m.tool_approval {
        if m.verdict_only() {
            // Counts are released only with details (older verdict-only
            // certificates carried them; they aren't repeated here).
            w.push("the auditee approved each of the agent's tool calls before it ran; a denial can keep evidence from the agent".into());
        } else {
            w.push(format!(
                "the auditee approved each of the agent's tool calls before it ran: {} approved, {} denied{}; a denial can keep evidence from the agent",
                a.approved,
                a.denied,
                if a.timed_out > 0 { format!(" ({} for lack of a decision)", a.timed_out) } else { String::new() }
            ));
        }
    }
    let blinded = m.auditor_messages.iter().filter(|x| x.blinded).count();
    if blinded > 0 {
        w.push(format!(
            "{blinded} blinded auditor message(s) the auditee could not read"
        ));
    }
    w
}
