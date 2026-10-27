//! AWS Nitro attestation document verification.
//!
//! The certificate chain is checked at the document's own timestamp, not the
//! verifier's clock. Nitro signing certificates live for hours, while audit
//! certificates must stay checkable for years; the signature still has to
//! chain to the pinned AWS root, so this only accepts documents that were
//! valid when the NSM produced them.

use anyhow::{anyhow, bail, Context, Result};
use rustls_pki_types::{CertificateDer, UnixTime};
use serde::Deserialize;
use serde_bytes::ByteBuf;
use serde_cbor::Value;
use std::collections::BTreeMap;
use std::time::Duration;

const AWS_NITRO_ROOT_PEM: &str = include_str!("aws-nitro-root.pem");
/// sha256 of the DER root certificate, checked at runtime as a guard against
/// the embedded PEM being edited.
const AWS_NITRO_ROOT_SHA256: &str =
    "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b";

#[derive(Deserialize, Debug, Clone)]
pub struct AttestationDoc {
    pub module_id: String,
    pub digest: String,
    pub timestamp: u64,
    pub pcrs: BTreeMap<usize, ByteBuf>,
    pub certificate: ByteBuf,
    pub cabundle: Vec<ByteBuf>,
    pub public_key: Option<ByteBuf>,
    pub user_data: Option<ByteBuf>,
    pub nonce: Option<ByteBuf>,
}

impl AttestationDoc {
    pub fn pcr_hex(&self, i: usize) -> String {
        self.pcrs
            .get(&i)
            .map(|v| hex::encode(v.as_ref()))
            .unwrap_or_default()
    }
}

fn root_der() -> Result<Vec<u8>> {
    let b64: String = AWS_NITRO_ROOT_PEM
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    use base64::Engine;
    let der = base64::engine::general_purpose::STANDARD.decode(b64)?;
    if crate::sha256_hex(&der) != AWS_NITRO_ROOT_SHA256 {
        bail!("embedded AWS Nitro root certificate does not match its pinned hash");
    }
    Ok(der)
}

/// Verify a COSE_Sign1 Nitro attestation document and return its contents.
/// Does not check PCRs, user data, nonce or public key: callers do that.
pub fn verify_document(cose: &[u8]) -> Result<AttestationDoc> {
    let value: Value = serde_cbor::from_slice(cose).context("attestation document is not CBOR")?;
    let items = match value {
        Value::Array(a) => a,
        Value::Tag(18, inner) => match *inner {
            Value::Array(a) => a,
            _ => bail!("COSE_Sign1 tag without array"),
        },
        _ => bail!("attestation document is not a COSE_Sign1 array"),
    };
    let [protected, _unprotected, payload, signature]: [Value; 4] = items
        .try_into()
        .map_err(|_| anyhow!("COSE_Sign1 must have 4 elements"))?;
    let (Value::Bytes(protected), Value::Bytes(payload), Value::Bytes(signature)) =
        (protected, payload, signature)
    else {
        bail!("COSE_Sign1 element types");
    };

    // Protected header must say ES384 (alg = -35).
    let header: Value = serde_cbor::from_slice(&protected).context("protected header")?;
    let alg = match &header {
        Value::Map(m) => m.get(&Value::Integer(1)).cloned(),
        _ => None,
    };
    if alg != Some(Value::Integer(-35)) {
        bail!("attestation document is not signed with ES384");
    }

    let doc: AttestationDoc =
        serde_cbor::from_slice(&payload).context("attestation document payload")?;
    if doc.digest != "SHA384" {
        bail!("unexpected PCR digest {}", doc.digest);
    }
    if doc.cabundle.is_empty() {
        bail!("empty CA bundle");
    }

    // Certificate chain: leaf -> cabundle[n-1] -> ... -> cabundle[0] == AWS root.
    let root = root_der()?;
    if doc.cabundle[0].as_ref() != root.as_slice() {
        bail!("CA bundle does not start with the AWS Nitro root");
    }
    let root_cert = CertificateDer::from(root.as_slice());
    let anchor =
        webpki::anchor_from_trusted_cert(&root_cert).map_err(|e| anyhow!("root anchor: {e:?}"))?;
    let intermediates: Vec<CertificateDer> = doc.cabundle[1..]
        .iter()
        .map(|c| CertificateDer::from(c.as_ref()))
        .collect();
    let leaf_der = CertificateDer::from(doc.certificate.as_ref());
    let leaf = webpki::EndEntityCert::try_from(&leaf_der)
        .map_err(|e| anyhow!("leaf certificate: {e:?}"))?;
    let at = UnixTime::since_unix_epoch(Duration::from_millis(doc.timestamp));
    let algs = &[
        webpki::ring::ECDSA_P384_SHA384,
        webpki::ring::ECDSA_P256_SHA256,
        webpki::ring::ECDSA_P384_SHA256,
    ];
    let anchors = [anchor];
    leaf.verify_for_usage(
        algs,
        &anchors,
        &intermediates,
        at,
        webpki::KeyUsage::client_auth(),
        None,
        None,
    )
    .or_else(|_| {
        leaf.verify_for_usage(
            algs,
            &anchors,
            &intermediates,
            at,
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
    })
    .map_err(|e| {
        anyhow!(
            "certificate chain does not verify to the AWS Nitro root at the document time: {e:?}"
        )
    })?;

    // COSE signature with the leaf key.
    let (_, cert) = x509_parser::parse_x509_certificate(&doc.certificate)
        .map_err(|e| anyhow!("leaf parse: {e}"))?;
    let spki = &cert.public_key().subject_public_key.data;
    let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(spki)
        .map_err(|e| anyhow!("leaf key is not P-384: {e}"))?;
    let sig = p384::ecdsa::Signature::from_slice(&signature)
        .map_err(|e| anyhow!("signature encoding: {e}"))?;
    let to_be_signed = serde_cbor::to_vec(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected.clone()),
        Value::Bytes(vec![]),
        Value::Bytes(payload.clone()),
    ]))?;
    use p384::ecdsa::signature::Verifier;
    key.verify(&to_be_signed, &sig)
        .map_err(|_| anyhow!("attestation document signature does not verify"))?;

    Ok(doc)
}

/// Expected measurements. Accepts nitro-cli's build output
/// (`{"Measurements": {"PCR0": ...}}`) or a flat `{"PCR0": ...}`.
#[derive(Debug, Clone)]
pub struct ExpectedPcrs {
    pub pcr0: String,
    pub pcr1: Option<String>,
    pub pcr2: Option<String>,
}

impl ExpectedPcrs {
    pub fn from_json(text: &str) -> Result<Self> {
        let v: serde_json::Value = serde_json::from_str(text)?;
        let m = v.get("Measurements").unwrap_or(&v);
        let get = |k: &str| {
            m.get(k)
                .and_then(|x| x.as_str())
                .map(|s| s.to_ascii_lowercase())
        };
        Ok(Self {
            pcr0: get("PCR0").ok_or_else(|| anyhow!("measurements file has no PCR0"))?,
            pcr1: get("PCR1"),
            pcr2: get("PCR2"),
        })
    }

    pub fn check(&self, doc: &AttestationDoc) -> Result<()> {
        let mut bad = Vec::new();
        let want = [
            (0, Some(&self.pcr0)),
            (1, self.pcr1.as_ref()),
            (2, self.pcr2.as_ref()),
        ];
        for (i, w) in want {
            if let Some(w) = w {
                let got = doc.pcr_hex(i);
                if &got != w {
                    bad.push(format!("PCR{i}: got {got}, want {w}"));
                }
            }
        }
        if !bad.is_empty() {
            bail!("enclave measurement mismatch:\n  {}", bad.join("\n  "));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    /// A real document from the timelock-proxy production enclave
    /// (2026-09-12). Its leaf certificate expired long ago, so this also
    /// checks that verification happens at the document's timestamp.
    #[test]
    fn verifies_real_document() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/timelock-ready-attestation.json"
        ))
        .unwrap();
        let doc_b64 = fixture["document_b64"].as_str().unwrap();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(doc_b64)
            .unwrap();
        let doc = verify_document(&bytes).unwrap();
        assert_eq!(doc.pcr_hex(0), fixture["pcr0"].as_str().unwrap());
        assert_eq!(doc.timestamp, fixture["timestamp_ms"].as_u64().unwrap());

        // Flip one payload byte: signature must fail.
        let mut tampered = bytes.clone();
        let n = tampered.len();
        tampered[n / 2] ^= 1;
        assert!(verify_document(&tampered).is_err());
    }
}
