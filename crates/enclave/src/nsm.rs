//! Nitro Security Module attestation. Dev mode returns no documents and
//! the enclave advertises `mode: "dev"`, which verifiers reject by default.

use anyhow::Result;

pub struct Attester {
    #[cfg(target_os = "linux")]
    fd: Option<i32>,
}

impl Attester {
    pub fn new(dev: bool) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            if dev {
                return Ok(Self { fd: None });
            }
            let fd = aws_nitro_enclaves_nsm_api::driver::nsm_init();
            if fd < 0 {
                anyhow::bail!("could not open /dev/nsm; not inside a Nitro Enclave? (use --dev for local testing)");
            }
            Ok(Self { fd: Some(fd) })
        }
        #[cfg(not(target_os = "linux"))]
        {
            if !dev {
                anyhow::bail!("Nitro attestation requires linux; run with --dev");
            }
            Ok(Self {})
        }
    }

    /// Attestation document over (user_data, public_key, nonce). None in dev mode.
    pub fn attest(&self, user_data: &[u8], public_key: &[u8], nonce: Option<&[u8]>) -> Result<Option<Vec<u8>>> {
        #[cfg(target_os = "linux")]
        {
            use aws_nitro_enclaves_nsm_api::api::{Request, Response};
            let Some(fd) = self.fd else { return Ok(None) };
            let req = Request::Attestation {
                user_data: Some(serde_bytes::ByteBuf::from(user_data.to_vec())),
                public_key: Some(serde_bytes::ByteBuf::from(public_key.to_vec())),
                nonce: nonce.map(|n| serde_bytes::ByteBuf::from(n.to_vec())),
            };
            match aws_nitro_enclaves_nsm_api::driver::nsm_process_request(fd, req) {
                Response::Attestation { document } => Ok(Some(document)),
                Response::Error(e) => anyhow::bail!("NSM error: {e:?}"),
                other => anyhow::bail!("unexpected NSM response: {other:?}"),
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (user_data, public_key, nonce);
            Ok(None)
        }
    }
}
