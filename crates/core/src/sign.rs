use crate::types::Signed;
use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{de::DeserializeOwned, Serialize};

fn message(domain: &str, body: &str) -> Vec<u8> {
    let mut m = Vec::with_capacity(domain.len() + 1 + body.len());
    m.extend_from_slice(domain.as_bytes());
    m.push(b'\n');
    m.extend_from_slice(body.as_bytes());
    m
}

pub fn sign<T: Serialize>(key: &SigningKey, domain: &str, body: &T) -> Result<Signed> {
    let body = serde_json::to_string(body)?;
    let sig = key.sign(&message(domain, &body));
    Ok(Signed {
        domain: domain.to_string(),
        body,
        public_key: hex::encode(key.verifying_key().to_bytes()),
        signature: hex::encode(sig.to_bytes()),
    })
}

pub fn parse_public_key(hex_key: &str) -> Result<VerifyingKey> {
    let bytes: [u8; 32] = hex::decode(hex_key)
        .context("public key hex")?
        .try_into()
        .map_err(|_| anyhow!("public key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| anyhow!("bad public key: {e}"))
}

impl Signed {
    /// Check the signature and domain, then parse the body.
    pub fn open<T: DeserializeOwned>(&self, domain: &str) -> Result<T> {
        if self.domain != domain {
            bail!("expected a {domain} signature, got {}", self.domain);
        }
        let key = parse_public_key(&self.public_key)?;
        let sig: [u8; 64] = hex::decode(&self.signature)
            .context("signature hex")?
            .try_into()
            .map_err(|_| anyhow!("signature must be 64 bytes"))?;
        key.verify(&message(&self.domain, &self.body), &ed25519_dalek::Signature::from_bytes(&sig))
            .map_err(|_| anyhow!("{domain}: signature does not verify"))?;
        serde_json::from_str(&self.body).with_context(|| format!("{domain}: body"))
    }

    /// Like `open`, but also require a specific signer.
    pub fn open_by<T: DeserializeOwned>(&self, domain: &str, signer_hex: &str) -> Result<T> {
        if !self.public_key.eq_ignore_ascii_case(signer_hex) {
            bail!("{domain}: signed by {}, expected {signer_hex}", self.public_key);
        }
        self.open(domain)
    }

    /// Stable identifier: sha256 over signer and body.
    pub fn id(&self) -> String {
        crate::sha256_hex(format!("{}\n{}\n{}", self.domain, self.public_key, self.body).as_bytes())
    }
}

pub fn signing_key_from_hex(seed_hex: &str) -> Result<SigningKey> {
    let seed: [u8; 32] = hex::decode(seed_hex.trim())
        .context("seed hex")?
        .try_into()
        .map_err(|_| anyhow!("seed must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&seed))
}

pub fn generate_signing_key() -> SigningKey {
    SigningKey::generate(&mut rand::rngs::OsRng)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_tamper() {
        let k = generate_signing_key();
        let s = sign(&k, "d", &serde_json::json!({"a": 1})).unwrap();
        let v: serde_json::Value = s.open("d").unwrap();
        assert_eq!(v["a"], 1);
        assert!(s.open::<serde_json::Value>("other").is_err());
        let mut t = s.clone();
        t.body = t.body.replace('1', "2");
        assert!(t.open::<serde_json::Value>("d").is_err());
    }
}
