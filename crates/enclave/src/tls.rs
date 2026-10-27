//! The enclave's TLS identity (adapted from timelock-proxy). The key pair is generated fresh at boot, never
//! persisted, never leaves the enclave. The attestation document binds to its
//! SubjectPublicKeyInfo. The certificate presented for that key can change:
//! self-signed at boot, then (optionally) a CA-issued chain obtained via ACME,
//! plus a transient TLS-ALPN-01 challenge certificate while validating.

use anyhow::{anyhow, Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::sync::{Arc, RwLock};

pub const ACME_ALPN: &[u8] = b"acme-tls/1";

#[derive(Clone)]
pub struct CertSnapshot {
    /// Leaf certificate currently presented.
    pub cert_der: Vec<u8>,
    pub cert_pem: String,
    pub cert_sha256: String,
    pub issuer: &'static str,
}

pub struct ServerIdentity {
    key: rcgen::KeyPair,
    signing_key: Arc<dyn rustls::sign::SigningKey>,
    /// DER SubjectPublicKeyInfo of the key. This is what goes into the
    /// attestation document's `user_data`.
    pub spki_der: Vec<u8>,
    pub spki_sha256: String,
    pub dns_names: Vec<String>,
    resolver: Arc<CertResolver>,
    server_config: Arc<rustls::ServerConfig>,
}

struct CertResolver {
    main: RwLock<(Arc<CertifiedKey>, CertSnapshot)>,
    challenge: RwLock<Option<(String, Arc<CertifiedKey>)>>,
}

impl std::fmt::Debug for CertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CertResolver")
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let wants_acme = hello
            .alpn()
            .map(|mut a| a.any(|p| p == ACME_ALPN))
            .unwrap_or(false);
        if wants_acme {
            let guard = self.challenge.read().unwrap();
            if let Some((name, ck)) = guard.as_ref() {
                // IP identifiers are validated with the reverse-DNS name as
                // SNI (RFC 8738), or none at all.
                let ok = match hello.server_name() {
                    Some(sni) => sni.eq_ignore_ascii_case(name) || sni.eq_ignore_ascii_case(&reverse_dns(name)),
                    None => name.parse::<std::net::IpAddr>().is_ok(),
                };
                if ok {
                    return Some(ck.clone());
                }
            }
            // An ACME-only client with no matching challenge gets nothing.
            return None;
        }
        Some(self.main.read().unwrap().0.clone())
    }
}

impl ServerIdentity {
    pub fn generate(dns_names: &[String]) -> Result<Self> {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .context("generating P-256 key")?;
        let spki_der = rcgen::PublicKeyData::subject_public_key_info(&key);
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
            .map_err(|e| anyhow!("signing key: {e}"))?;

        let mut names = vec!["attest.invalid".to_string()];
        names.extend(dns_names.iter().cloned());
        let mut params = rcgen::CertificateParams::new(names).context("cert params")?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "attest enclave");
        let cert = params.self_signed(&key).context("self-signing cert")?;
        let snapshot = CertSnapshot {
            cert_der: cert.der().to_vec(),
            cert_pem: cert.pem(),
            cert_sha256: attest_core::sha256_hex(cert.der()),
            issuer: "self-signed",
        };
        let ck = Arc::new(CertifiedKey::new(vec![cert.der().clone()], signing_key.clone()));
        let resolver = Arc::new(CertResolver {
            main: RwLock::new((ck, snapshot)),
            challenge: RwLock::new(None),
        });

        let mut server_config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone());
        // Server preference: HTTP/1.1 first, so a client that offers both
        // gets HTTP; ACME validators offer only acme-tls/1 and still get it.
        server_config.alpn_protocols = vec![b"http/1.1".to_vec(), ACME_ALPN.to_vec()];

        Ok(Self {
            spki_sha256: attest_core::sha256_hex(&spki_der),
            spki_der,
            dns_names: dns_names.to_vec(),
            key,
            signing_key,
            resolver,
            server_config: Arc::new(server_config),
        })
    }

    pub fn server_config(&self) -> Arc<rustls::ServerConfig> {
        self.server_config.clone()
    }

    pub fn current(&self) -> CertSnapshot {
        self.resolver.main.read().unwrap().1.clone()
    }

    /// CSR for the enclave key covering `names`.
    pub fn csr_der(&self, names: &[String]) -> Result<Vec<u8>> {
        let mut params = rcgen::CertificateParams::new(names.to_vec()).context("csr params")?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        let csr = params.serialize_request(&self.key).context("serializing csr")?;
        Ok(csr.der().to_vec())
    }

    /// Present a TLS-ALPN-01 challenge certificate for `name` to ACME clients.
    pub fn set_challenge(&self, name: &str, key_auth_digest: &[u8]) -> Result<()> {
        let mut params = rcgen::CertificateParams::new(vec![name.to_string()]).context("challenge params")?;
        params
            .custom_extensions
            .push(rcgen::CustomExtension::new_acme_identifier(key_auth_digest));
        // A throwaway key is fine: the challenge cert carries no trust.
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let cert = params.self_signed(&key).context("challenge cert")?;
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let sk = rustls::crypto::ring::sign::any_supported_type(&key_der)
            .map_err(|e| anyhow!("challenge signing key: {e}"))?;
        let ck = Arc::new(CertifiedKey::new(vec![cert.der().clone()], sk));
        *self.resolver.challenge.write().unwrap() = Some((name.to_ascii_lowercase(), ck));
        Ok(())
    }

    pub fn clear_challenge(&self) {
        *self.resolver.challenge.write().unwrap() = None;
    }

    /// Install a CA-issued chain (PEM, leaf first) for the enclave key.
    pub fn install_chain_pem(&self, chain_pem: &str) -> Result<()> {
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile_certs(chain_pem)?;
        let leaf = certs.first().ok_or_else(|| anyhow!("empty chain"))?.clone();
        // The chain must be for our key.
        let (_, parsed) = x509_leaf_spki(&leaf)?;
        if parsed != self.spki_der {
            anyhow::bail!("issued certificate is not for the enclave key");
        }
        let leaf_pem = pem_encode("CERTIFICATE", &leaf);
        let snapshot = CertSnapshot {
            cert_sha256: attest_core::sha256_hex(&leaf),
            cert_der: leaf.to_vec(),
            cert_pem: leaf_pem,
            issuer: "acme",
        };
        let ck = Arc::new(CertifiedKey::new(certs, self.signing_key.clone()));
        *self.resolver.main.write().unwrap() = (ck, snapshot);
        Ok(())
    }
}

fn rustls_pemfile_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut out = Vec::new();
    let mut in_block = false;
    let mut b64 = String::new();
    for line in pem.lines() {
        let l = line.trim();
        if l == "-----BEGIN CERTIFICATE-----" {
            in_block = true;
            b64.clear();
        } else if l == "-----END CERTIFICATE-----" {
            in_block = false;
            let der = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &b64)
                .context("PEM base64")?;
            out.push(CertificateDer::from(der));
        } else if in_block {
            b64.push_str(l);
        }
    }
    Ok(out)
}

fn pem_encode(label: &str, der: &[u8]) -> String {
    let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, der);
    let mut s = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(chunk).unwrap());
        s.push('\n');
    }
    s.push_str(&format!("-----END {label}-----\n"));
    s
}

/// Extract the SubjectPublicKeyInfo DER from a certificate. Minimal DER walk:
/// Certificate -> TBSCertificate -> [version] serial sigalg issuer validity
/// subject subjectPublicKeyInfo.
fn x509_leaf_spki(cert: &[u8]) -> Result<(usize, Vec<u8>)> {
    fn tlv(buf: &[u8], pos: usize) -> Result<(u8, usize, usize)> {
        let tag = *buf.get(pos).ok_or_else(|| anyhow!("der eof"))?;
        let mut p = pos + 1;
        let first = *buf.get(p).ok_or_else(|| anyhow!("der eof"))?;
        p += 1;
        let len = if first & 0x80 == 0 {
            first as usize
        } else {
            let n = (first & 0x7f) as usize;
            let mut l = 0usize;
            for _ in 0..n {
                l = (l << 8) | *buf.get(p).ok_or_else(|| anyhow!("der eof"))? as usize;
                p += 1;
            }
            l
        };
        Ok((tag, p, len))
    }
    let (_, tbs_start, _) = tlv(cert, 0)?; // Certificate SEQUENCE
    let (_, mut p, tbs_len) = tlv(cert, tbs_start)?; // TBSCertificate
    let end = p + tbs_len;
    // optional version [0]
    let (tag, cs, cl) = tlv(cert, p)?;
    if tag == 0xa0 {
        p = cs + cl;
    }
    for _ in 0..5 {
        // serial, sigalg, issuer, validity, subject
        let (_, cs, cl) = tlv(cert, p)?;
        p = cs + cl;
    }
    let (tag, cs, cl) = tlv(cert, p)?;
    if tag != 0x30 || cs + cl > end {
        anyhow::bail!("unexpected der layout");
    }
    Ok((p, cert[p..cs + cl].to_vec()))
}

/// "1.2.3.4" -> "4.3.2.1.in-addr.arpa" (and the ip6.arpa form for IPv6).
fn reverse_dns(name: &str) -> String {
    match name.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            let hex: String = v6.octets().iter().map(|b| format!("{b:02x}")).collect();
            let mut out: Vec<String> = hex.chars().rev().map(|c| c.to_string()).collect();
            out.push("ip6.arpa".into());
            out.join(".")
        }
        Err(_) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn ip_names_become_ip_sans() {
        let p = rcgen::CertificateParams::new(vec!["16.147.102.127".to_string(), "example.com".to_string()]).unwrap();
        assert!(matches!(p.subject_alt_names[0], rcgen::SanType::IpAddress(_)));
        assert!(matches!(p.subject_alt_names[1], rcgen::SanType::DnsName(_)));
        assert_eq!(super::reverse_dns("16.147.102.127"), "127.102.147.16.in-addr.arpa");
    }
}
