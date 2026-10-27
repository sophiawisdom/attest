//! Turn a directory into a deterministic tar and its tree hash.

use anyhow::{bail, Context, Result};
use attest_core::tree::{normalize_path, sha256, tree_hash};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

pub struct GitInfo {
    pub head: Option<String>,
    pub remote: Option<String>,
    pub dirty: bool,
    pub is_repo: bool,
}

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git").arg("-C").arg(dir).args(args).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub fn git_info(dir: &Path) -> GitInfo {
    let is_repo = git(dir, &["rev-parse", "--is-inside-work-tree"]).as_deref() == Some("true");
    if !is_repo {
        return GitInfo { head: None, remote: None, dirty: false, is_repo };
    }
    GitInfo {
        head: git(dir, &["rev-parse", "HEAD"]),
        remote: git(dir, &["remote", "get-url", "origin"]).filter(|s| !s.is_empty()),
        dirty: git(dir, &["status", "--porcelain", "--untracked-files=no"]).map(|s| !s.is_empty()).unwrap_or(false),
        is_repo,
    }
}

/// (relative path, contents). In a git checkout: tracked files only.
/// Otherwise: every regular file, skipping `.git`. Symlinks are skipped.
pub fn collect(dir: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    let mut paths = Vec::new();
    if git_info(dir).is_repo {
        let out = Command::new("git").arg("-C").arg(dir).args(["ls-files", "-z"]).output()?;
        if !out.status.success() {
            bail!("git ls-files failed");
        }
        for p in out.stdout.split(|b| *b == 0).filter(|p| !p.is_empty()) {
            paths.push(String::from_utf8(p.to_vec()).context("non-UTF-8 path in repository")?);
        }
    } else {
        for e in walkdir::WalkDir::new(dir).into_iter().filter_entry(|e| e.file_name() != ".git") {
            let e = e?;
            if e.file_type().is_file() {
                let rel = e.path().strip_prefix(dir)?.to_str().context("non-UTF-8 path")?.to_string();
                paths.push(rel);
            }
        }
    }
    let mut files = Vec::new();
    let mut skipped = 0;
    for p in paths {
        let full = dir.join(&p);
        let meta = match std::fs::symlink_metadata(&full) {
            Ok(m) => m,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };
        if !meta.file_type().is_file() {
            skipped += 1;
            continue;
        }
        let norm = normalize_path(&p).with_context(|| format!("unusable path {p:?}"))?;
        files.push((norm, std::fs::read(&full).with_context(|| format!("reading {}", full.display()))?));
    }
    if skipped > 0 {
        eprintln!("note: skipped {skipped} symlinks, submodules or missing files");
    }
    if files.is_empty() {
        bail!("no files to send in {}", dir.display());
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(files)
}

pub fn tar_and_hash(files: &[(String, Vec<u8>)]) -> Result<(Vec<u8>, String)> {
    let mut b = tar::Builder::new(Vec::new());
    let mut digests = BTreeMap::new();
    for (path, bytes) in files {
        let mut h = tar::Header::new_gnu();
        h.set_size(bytes.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(0);
        h.set_uid(0);
        h.set_gid(0);
        h.set_entry_type(tar::EntryType::Regular);
        h.set_cksum();
        b.append_data(&mut h, path, bytes.as_slice())?;
        digests.insert(path.clone(), sha256(bytes));
    }
    Ok((b.into_inner()?, tree_hash(&digests)))
}
