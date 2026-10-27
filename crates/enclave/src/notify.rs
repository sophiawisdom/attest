//! Email notifications through Amazon SES, for people. (Agents poll.)
//!
//! Not an open relay: SES runs in sandbox mode, where it only delivers to
//! addresses that have confirmed. Entering an address makes SES send that
//! address one confirmation email; nothing else reaches it until the link is
//! clicked. Those confirmation requests are rate-limited. Messages say only
//! that something happened in a session.

use crate::sessions::Ctx;
use attest_core::Role;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
pub struct EmailConfig {
    /// Sender address; must itself be verified in SES by the operator.
    pub from: String,
    pub region: String,
}

/// Confirmation requests allowed per hour, across all sessions.
const VERIFICATIONS_PER_HOUR: usize = 30;

#[derive(Default)]
pub struct Limiter {
    recent: Mutex<VecDeque<u64>>,
}

impl Limiter {
    fn allow(&self) -> bool {
        let now = attest_core::now_ms();
        let mut q = self.recent.lock().unwrap();
        while q.front().is_some_and(|t| now - t > 3_600_000) {
            q.pop_front();
        }
        if q.len() >= VERIFICATIONS_PER_HOUR {
            return false;
        }
        q.push_back(now);
        true
    }
}

/// Check or start confirmation of `email` and record the result on the session.
pub async fn verify(ctx: Arc<Ctx>, session_id: String, role: Role, email: String) {
    let (Some(cfg), Some(session)) = (ctx.email.clone(), ctx.store.get(&session_id)) else {
        return;
    };
    let status = if ctx.dev {
        crate::log(&format!("dev outbox: would ask SES to verify {email}"));
        "verified"
    } else {
        match crate::aws::verification_status(&ctx.net, ctx.dev, &cfg.region, &email).await {
            Ok(Some(s)) if s == "Success" => "verified",
            Ok(Some(s)) if s == "Pending" => "pending",
            Ok(_) if !ctx.email_limiter.allow() => "rate_limited",
            Ok(_) => match crate::aws::request_verification(&ctx.net, ctx.dev, &cfg.region, &email)
                .await
            {
                Ok(()) => "pending",
                Err(e) => {
                    crate::log(&format!("ses verify: {e:#}"));
                    "error"
                }
            },
            Err(e) => {
                crate::log(&format!("ses status: {e:#}"));
                "error"
            }
        }
    };
    session.set_email_status(role, &email, status);
}

pub async fn deliver(
    ctx: Arc<Ctx>,
    session_id: String,
    role: Role,
    email: String,
    verified: bool,
    text: String,
) {
    let (Some(cfg), Some(session)) = (ctx.email.clone(), ctx.store.get(&session_id)) else {
        return;
    };
    let server = ctx
        .public_name
        .clone()
        .unwrap_or_else(|| "the attest server".into());
    let subject = format!("attest: {}", text.chars().take(90).collect::<String>());
    let body = format!(
        "{text}\n\nSession {} on {server}. Open your session link to continue.\n\nYou are getting this because this address was entered and confirmed for notifications in an attest session.",
        &session.id[..8]
    );
    if ctx.dev {
        crate::log(&format!("dev outbox: to {email}: {subject}"));
        return;
    }
    if !verified {
        // Confirmation may have happened since; check before giving up.
        match crate::aws::verification_status(&ctx.net, ctx.dev, &cfg.region, &email).await {
            Ok(Some(s)) if s == "Success" => session.set_email_status(role, &email, "verified"),
            _ => return,
        }
    }
    if let Err(e) = crate::aws::send_email(
        &ctx.net,
        ctx.dev,
        &cfg.region,
        &cfg.from,
        &email,
        &subject,
        &body,
    )
    .await
    {
        crate::log(&format!("email for session {}: {e:#}", &session.id[..8]));
    }
}
