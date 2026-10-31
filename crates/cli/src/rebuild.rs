//! `attest verify-service --rebuild`: build the enclave image from the
//! server's source commit on this machine, so the expected measurements come
//! from the source rather than from a file someone published.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

fn run(cmd: &mut Command) -> Result<()> {
    let st = cmd.status().with_context(|| format!("running {cmd:?}"))?;
    if !st.success() {
        bail!("{cmd:?} failed ({st})");
    }
    Ok(())
}

/// Check out `commit` from `repo` and run build/build-eif.sh in it. Returns
/// the path of the pcrs.json it wrote. Builds go under ~/.cache/attest so a
/// rerun reuses the checkout (the docker builder keeps its own cache unless
/// `fresh`).
pub fn build(repo: &str, commit: &str, fresh: bool) -> Result<PathBuf> {
    if Command::new("nitro-cli").arg("--version").output().is_err() {
        bail!(
            "--rebuild needs docker (with buildx) and nitro-cli 1.5.0 on Linux. The image is arm64 \
             (Graviton), so an arm64 Linux machine is simplest, e.g. Amazon Linux 2023 on Graviton: \
             `sudo dnf install -y aws-nitro-enclaves-cli docker git`"
        );
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    let dir = PathBuf::from(home).join(".cache/attest/rebuild").join(commit);
    if !dir.join(".git").exists() {
        std::fs::create_dir_all(&dir)?;
        run(Command::new("git").arg("init").arg("-q").arg(&dir))?;
    }
    eprintln!("== fetching {repo} at {commit}");
    run(Command::new("git").arg("-C").arg(&dir).args(["fetch", "-q", "--depth", "1", repo, commit]))?;
    run(Command::new("git").arg("-C").arg(&dir).args(["checkout", "-q", "--force", "FETCH_HEAD"]))?;
    run(Command::new("git").arg("-C").arg(&dir).args(["clean", "-q", "-fdx", "-e", "build/out"]))?;
    eprintln!("== building (this takes a while; FRESH builds take longer)");
    let mut b = Command::new("bash");
    b.arg(dir.join("build/build-eif.sh")).current_dir(&dir);
    // The service runs on Graviton (arm64) unless told otherwise.
    b.env("ARCH", std::env::var("ATTEST_ARCH").unwrap_or_else(|_| "aarch64".into()));
    if fresh {
        b.env("FRESH", "1");
    }
    run(&mut b)?;
    Ok(dir.join("build/out/pcrs.json"))
}

/// PCR0-2 of a nitro-cli pcrs.json, for comparing two of them.
pub fn pcrs(json: &str) -> Result<[String; 3]> {
    let v: Value = serde_json::from_str(json)?;
    let m = &v["Measurements"];
    let g = |k: &str| m[k].as_str().unwrap_or("").to_ascii_lowercase();
    Ok([g("PCR0"), g("PCR1"), g("PCR2")])
}
