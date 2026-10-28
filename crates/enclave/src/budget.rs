//! Limits on what sessions keep in enclave memory, set by the operator.
//!
//! Enclave memory is split (fractions of MemTotal):
//!   40%  jailed agents (cgroups::jails_memory)
//!   30%  copies of code held for runs and disclosures (sessions::code_memory)
//!   15%  session state, this budget: snapshots, traces, code indexes
//!   15%  everything else: the root filesystem, blob cache, Python
//!        sandbox, request buffers
//! The operator may move the session budget between 64 MiB and 25% of
//! memory, and set how many sessions may exist at once. Both only affect
//! availability: a lower limit refuses new work, never drops a session,
//! and sessions taken over from another enclave are always kept.

use anyhow::{ensure, Result};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};

pub const DEFAULT_MAX_SESSIONS: usize = 100;
pub const MAX_MAX_SESSIONS: usize = 10_000;

static MAX_SESSIONS: AtomicUsize = AtomicUsize::new(DEFAULT_MAX_SESSIONS);
/// Bytes; 0 until set (then the default share of memory applies).
static LIMIT: AtomicUsize = AtomicUsize::new(0);
/// The `at_ms` of the last limits change applied, so an old one can't be replayed.
static LAST_CHANGE: AtomicU64 = AtomicU64::new(0);

/// Compressed trace bytes held, across all runs.
pub static TRACES: AtomicUsize = AtomicUsize::new(0);
/// Estimated size of uploaded code's in-memory indexes.
pub static INDEXES: AtomicUsize = AtomicUsize::new(0);
/// Sessions' state, as last measured (its serialized size, doubled for
/// in-memory overhead).
pub static STATES: AtomicUsize = AtomicUsize::new(0);

fn mem_total() -> usize {
    crate::cgroups::mem_total() as usize
}

pub fn default_limit() -> usize {
    mem_total() / 100 * 15
}

fn bounds() -> (usize, usize) {
    (64 << 20, (mem_total() / 4).max(64 << 20))
}

pub fn max_sessions() -> usize {
    MAX_SESSIONS.load(Relaxed)
}

pub fn limit() -> usize {
    match LIMIT.load(Relaxed) {
        0 => default_limit(),
        n => n,
    }
}

pub fn used() -> usize {
    TRACES.load(Relaxed) + INDEXES.load(Relaxed) + STATES.load(Relaxed)
}

/// Apply limits (from the config at boot, or from the operator later).
/// Out-of-range values are clamped. Returns what applies now.
pub fn set(max_sessions: Option<usize>, memory_mib: Option<usize>) -> (usize, usize) {
    if let Some(n) = max_sessions {
        MAX_SESSIONS.store(clamp_sessions(n), Relaxed);
    }
    if let Some(m) = memory_mib {
        LIMIT.store(clamp_memory(m), Relaxed);
    }
    (self::max_sessions(), limit() >> 20)
}

fn clamp_sessions(n: usize) -> usize {
    n.clamp(1, MAX_MAX_SESSIONS)
}

/// MiB in, bytes out.
fn clamp_memory(mib: usize) -> usize {
    let (lo, hi) = bounds();
    mib.saturating_mul(1 << 20).clamp(lo, hi)
}

/// Refuse new work that would take `extra` more bytes of session memory.
pub fn ensure_room(extra: usize) -> Result<()> {
    ensure!(
        used().saturating_add(extra) <= limit(),
        "this server's memory for sessions is full; try again later"
    );
    Ok(())
}

pub fn add(counter: &AtomicUsize, n: usize) {
    counter.fetch_add(n, Relaxed);
}

/// Saturating, so an accounting slip can't wrap the gauge around.
pub fn sub(counter: &AtomicUsize, n: usize) {
    let _ = counter.try_update(Relaxed, Relaxed, |v| Some(v.saturating_sub(n)));
}

/// Replace a measured amount: `old` out, `new` in.
pub fn remeasure(counter: &AtomicUsize, old: usize, new: usize) {
    if new >= old {
        add(counter, new - old);
    } else {
        sub(counter, old - new);
    }
}

const LIMITS: &[u8] = b"attest-limits/1";

/// `POST /api/internal/limits`: the operator changes the limits live.
/// Body: {max_sessions?, session_memory_mib?, at_ms, mac}, where mac is
/// the handoff-token MAC over the domain and the three values as decimal
/// strings ("" for one left out). `at_ms` must be within five minutes of
/// the enclave's clock and newer than the last change. An empty change
/// just reports the limits and current use.
pub fn change(token: Option<&str>, body: &serde_json::Value, sessions: usize) -> Result<serde_json::Value> {
    use anyhow::Context;
    let token = token.filter(|t| t.len() >= 16).context("limits can't be changed on this enclave (no handoff token)")?;
    let num = |k: &str| -> Result<Option<u64>> {
        match &body[k] {
            serde_json::Value::Null => Ok(None),
            v => Ok(Some(v.as_u64().with_context(|| format!("{k} must be a whole number"))?)),
        }
    };
    let (n, mib, at) = (num("max_sessions")?, num("session_memory_mib")?, num("at_ms")?.context("at_ms is required")?);
    let s = |v: Option<u64>| v.map(|v| v.to_string()).unwrap_or_default();
    let (n_s, mib_s, at_s) = (s(n), s(mib), at.to_string());
    ensure!(
        crate::handoff::mac_ok(token, &[LIMITS, n_s.as_bytes(), mib_s.as_bytes(), at_s.as_bytes()], &body["mac"]),
        "wrong handoff token"
    );
    let now = attest_core::now_ms();
    ensure!(now.abs_diff(at) < 5 * 60 * 1000, "at_ms is more than five minutes from the enclave's clock");
    LAST_CHANGE
        .try_update(Relaxed, Relaxed, |last| (at > last).then_some(at))
        .map_err(|_| anyhow::anyhow!("a newer limits change was already applied"))?;
    let (max_sessions, memory_mib) = set(n.map(|v| v as usize), mib.map(|v| v as usize));
    crate::log(&format!("limits set: {max_sessions} sessions, {memory_mib} MiB of session memory"));
    Ok(serde_json::json!({
        "max_sessions": max_sessions,
        "session_memory_mib": memory_mib,
        "session_memory_max_mib": bounds().1 >> 20,
        "sessions": sessions,
        "session_memory_used_mib": used() >> 20,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The limits are process-wide and other tests create sessions, so
    // this test changes none of them.
    #[test]
    fn limits_clamp_and_replays_fail() {
        assert_eq!(clamp_sessions(0), 1);
        assert_eq!(clamp_sessions(1 << 40), MAX_MAX_SESSIONS);
        assert_eq!(clamp_memory(1), bounds().0);
        assert_eq!(clamp_memory(1 << 40), bounds().1);
        let token = "0123456789abcdef0123";
        let at = attest_core::now_ms();
        let body = |at: u64, tok: &str| {
            let mac = crate::handoff::mac(tok, &[LIMITS, b"", b"", at.to_string().as_bytes()]);
            serde_json::json!({"at_ms": at, "mac": mac})
        };
        assert!(change(Some(token), &body(at, "wrong-token-wrong-token"), 0).is_err());
        assert!(change(None, &body(at, token), 0).is_err());
        assert_eq!(change(Some(token), &body(at, token), 3).unwrap()["sessions"], 3);
        assert!(change(Some(token), &body(at, token), 0).is_err(), "replayed at_ms");
        assert!(change(Some(token), &body(at - 10 * 60 * 1000, token), 0).is_err(), "stale");
        assert!(change(Some(token), &body(at + 1, token), 0).is_ok());
        let counter = AtomicUsize::new(5);
        sub(&counter, 9);
        assert_eq!(counter.load(Relaxed), 0);
    }
}
