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
/// SES calls of any kind (status checks, confirmations, sends) per hour.
const SES_CALLS_PER_HOUR: usize = 600;
/// Notification tasks doing network work at once; more are dropped.
const MAX_IN_FLIGHT: usize = 8;

pub struct Limiter {
    per_hour: usize,
    recent: Mutex<VecDeque<std::time::Instant>>,
}

impl Default for Limiter {
    fn default() -> Self {
        Self::new(VERIFICATIONS_PER_HOUR)
    }
}

impl Limiter {
    fn new(per_hour: usize) -> Self {
        Self { per_hour, recent: Mutex::default() }
    }

    fn allow(&self) -> bool {
        let now = std::time::Instant::now();
        let mut q = self.recent.lock().unwrap_or_else(|p| p.into_inner());
        while q
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) > std::time::Duration::from_secs(3600))
        {
            q.pop_front();
        }
        if q.len() >= self.per_hour {
            return false;
        }
        q.push_back(now);
        true
    }
}

fn ses_calls() -> &'static Limiter {
    static L: std::sync::OnceLock<Limiter> = std::sync::OnceLock::new();
    L.get_or_init(|| Limiter::new(SES_CALLS_PER_HOUR))
}

/// A slot for one notification task, or None if too many are running.
fn slot() -> Option<tokio::sync::SemaphorePermit<'static>> {
    static S: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    let p = S.get_or_init(|| tokio::sync::Semaphore::new(MAX_IN_FLIGHT)).try_acquire().ok();
    if p.is_none() {
        crate::log("notifications: too many in flight; dropping one");
    }
    p
}

/// Check or start confirmation of `email` and record the result on the session.
pub async fn verify(ctx: Arc<Ctx>, session_id: String, role: Role, email: String) {
    let (Some(cfg), Some(session)) = (ctx.email.clone(), ctx.store.get(&session_id)) else {
        return;
    };
    let Some(_slot) = slot() else {
        session.set_email_status(role, &email, "rate_limited");
        return;
    };
    let status = if ctx.dev {
        crate::log(&format!("dev outbox: would ask SES to verify {email}"));
        "verified"
    } else if !ses_calls().allow() {
        "rate_limited"
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
    let Some(_slot) = slot() else { return };
    if !ses_calls().allow() || (!verified && !ses_calls().allow()) {
        crate::log(&format!("email for session {}: SES rate limit reached; dropped", &session.id[..8]));
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
