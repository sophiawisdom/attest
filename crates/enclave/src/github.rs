//! Importing code straight from GitHub. The auditee gives a read-only token
//! (none for a public repository);
//! the enclave resolves the ref to a commit and streams that commit's archive
//! over its own TLS connections to api.github.com and codeload.github.com,
//! so neither the parent nor the operator sees the token or the code. The
//! token is used for these two requests and then dropped: it's never stored.

use crate::net::Net;
use anyhow::{anyhow, bail, ensure, Context, Result};
use std::time::Duration;

pub const API: &str = "api.github.com";
pub const CODELOAD: &str = "codeload.github.com";

/// "owner/name", checked.
pub fn check_repo(repo: &str) -> Result<()> {
    let ok = |s: &str| !s.is_empty() && s.len() <= 100 && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)) && s != "." && s != "..";
    match repo.split_once('/') {
        Some((o, n)) if ok(o) && ok(n) => Ok(()),
        _ => bail!("repo must be owner/name"),
    }
}

/// A branch, tag or commit name, checked.
pub fn check_ref(r: &str) -> Result<()> {
    ensure!(
        !r.is_empty()
            && r.len() <= 200
            && !r.contains("..")
            && !r.starts_with('/')
            && r.chars().all(|c| c.is_ascii_alphanumeric() || "-_./".contains(c)),
        "ref must be a branch, tag or commit"
    );
    Ok(())
}

/// Request headers; no authorization for a public repository.
fn headers(token: &str) -> Vec<(&'static str, String)> {
    let mut h = vec![
        ("user-agent", "attest-enclave".to_string()),
        ("x-github-api-version", "2022-11-28".into()),
        ("accept", "application/vnd.github+json".into()),
    ];
    if !token.is_empty() {
        h.push(("authorization", format!("Bearer {token}")));
    }
    h
}

fn explain(status: u16, what: &str) -> anyhow::Error {
    match status {
        401 => anyhow!("GitHub rejected the token (expired or mistyped?)"),
        403 | 429 => anyhow!("GitHub refused {what} (rate limit, or the token lacks read access to contents)"),
        404 | 422 => anyhow!("GitHub found no such repository or ref, or the token can't read it"),
        s => anyhow!("GitHub answered {what} with HTTP {s}"),
    }
}

/// The commit `r` names in `repo`.
pub async fn resolve(net: &Net, repo: &str, r: &str, token: &str) -> Result<String> {
    let h = headers(token);
    let mut hv: Vec<(&str, &str)> = h.iter().map(|(k, v)| (*k, v.as_str())).collect();
    hv.retain(|(k, _)| *k != "accept");
    hv.push(("accept", "application/vnd.github.sha"));
    let resp = net
        .request_full("GET", true, API, 443, &format!("/repos/{repo}/commits/{r}"), &hv, Vec::new(), Duration::from_secs(30))
        .await?;
    if resp.status != 200 {
        return Err(explain(resp.status, "the ref lookup"));
    }
    let sha = String::from_utf8_lossy(&resp.body).trim().to_string();
    ensure!(sha.len() == 40 && sha.chars().all(|c| c.is_ascii_hexdigit()), "GitHub returned no commit for that ref");
    Ok(sha)
}

/// The gzipped tar archive of `commit`, as a stream.
pub async fn archive(net: &Net, repo: &str, commit: &str, token: &str) -> Result<hyper::body::Incoming> {
    let h = headers(token);
    let hv: Vec<(&str, &str)> = h.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let resp = net
        .request_full("GET", true, API, 443, &format!("/repos/{repo}/tarball/{commit}"), &hv, Vec::new(), Duration::from_secs(30))
        .await?;
    if resp.status != 302 {
        return Err(explain(resp.status, "the archive request"));
    }
    // A short-lived link to codeload; it carries its own authorization.
    let loc = resp.header("location").context("GitHub gave no archive location")?;
    let url = url::Url::parse(loc).context("GitHub gave a malformed archive location")?;
    ensure!(url.scheme() == "https" && url.host_str() == Some(CODELOAD), "GitHub sent the archive somewhere unexpected");
    let path = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_string(),
    };
    let resp = net
        .get_streaming(CODELOAD, &path, &[("user-agent", "attest-enclave")], Duration::from_secs(60))
        .await?;
    if resp.status() != 200 {
        return Err(explain(resp.status().as_u16(), "the archive download"));
    }
    Ok(resp.into_body())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_checked() {
        assert!(check_repo("sophiawisdom/attest").is_ok());
        assert!(check_repo("a/b/c").is_err());
        assert!(check_repo("../x").is_err());
        assert!(check_repo("a/..").is_err());
        assert!(check_repo("a?/b").is_err());
        assert!(check_ref("main").is_ok());
        assert!(check_ref("release/1.2").is_ok());
        assert!(check_ref("a..b").is_err());
        assert!(check_ref("x?y").is_err());
        assert!(check_ref("").is_err());
    }
}
