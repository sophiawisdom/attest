//! Notifications: webhooks (for agents) and email. Payloads say only that
//! something happened; the party then polls the session for details.

use crate::sessions::{Ctx, NotifyPrefs};
use attest_core::Role;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Debug, serde::Deserialize)]
pub struct EmailConfig {
    /// Resend (https://resend.com) API key.
    pub resend_api_key: String,
    /// Sender, e.g. "attest <notify@example.com>"; its domain must be verified with Resend.
    pub from: String,
}

#[allow(clippy::too_many_arguments)]
pub async fn deliver(ctx: Arc<Ctx>, prefs: NotifyPrefs, session_id: String, role: Role, seq: u64, kind: String, text: String, important: bool) {
    if let Some(url) = prefs.webhook_url {
        let body = json!({
            "service": "attest",
            "session_id": session_id,
            "role": role,
            "event": {"seq": seq, "kind": kind, "text": text},
            "hint": "GET /api/sessions/{session_id} with your link's token for details",
        });
        if let Err(e) = webhook(&ctx, &url, serde_json::to_vec(&body).unwrap_or_default()).await {
            crate::log(&format!("webhook for session {}: {e:#}", &session_id[..8]));
        }
    }
    if important {
        if let (Some(to), Some(cfg)) = (prefs.email, ctx.email.clone()) {
            if let Err(e) = email(&ctx, &cfg, &to, &session_id, &text).await {
                crate::log(&format!("email for session {}: {e:#}", &session_id[..8]));
            }
        }
    }
}

async fn webhook(ctx: &Ctx, url: &str, body: Vec<u8>) -> anyhow::Result<()> {
    let u = url::Url::parse(url)?;
    let host = u.host_str().ok_or_else(|| anyhow::anyhow!("no host"))?;
    let path = match u.query() {
        Some(q) => format!("{}?{q}", u.path()),
        None => u.path().to_string(),
    };
    let r = ctx.net.request(true, host, 443, &path, &[("user-agent", "attest-enclave")], body, Duration::from_secs(20)).await?;
    anyhow::ensure!(r.status < 400, "HTTP {}", r.status);
    Ok(())
}

async fn email(ctx: &Ctx, cfg: &EmailConfig, to: &str, session_id: &str, text: &str) -> anyhow::Result<()> {
    let host = ctx.info.domain.clone().unwrap_or_else(|| "the attest server".into());
    let body = json!({
        "from": cfg.from,
        "to": [to],
        "subject": format!("attest: {}", text.chars().take(90).collect::<String>()),
        "text": format!("{text}\n\nSession {} on {host}. Open your session link to continue.\n\nYou are getting this because someone set this address for notifications in an attest session.", &session_id[..8]),
    });
    let auth = format!("Bearer {}", cfg.resend_api_key);
    let r = ctx
        .net
        .request(true, "api.resend.com", 443, "/emails", &[("authorization", &auth)], serde_json::to_vec(&body)?, Duration::from_secs(20))
        .await?;
    anyhow::ensure!(r.status < 400, "HTTP {}: {}", r.status, String::from_utf8_lossy(&r.body[..r.body.len().min(300)]));
    Ok(())
}
