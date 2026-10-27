//! The auditee's code, held in enclave memory, plus the read-only tools the
//! model gets over it.

use anyhow::{bail, Context, Result};
use attest_core::tree::{normalize_path, sha256, tree_hash};
use attest_core::{scan, CodeInfo, ScanCounts};
use regex::RegexBuilder;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

pub struct File {
    pub bytes: Vec<u8>,
    pub digest: [u8; 32],
    /// None for binary files.
    pub text: Option<String>,
}

pub struct Bundle {
    pub files: BTreeMap<String, File>,
    pub dirs: BTreeSet<String>,
    pub info: CodeInfo,
}

const MAX_FILES: usize = 2_000_000;

fn as_text(bytes: &[u8]) -> Option<String> {
    let head = &bytes[..bytes.len().min(8192)];
    if head.contains(&0) {
        return None;
    }
    Some(String::from_utf8_lossy(bytes).into_owned())
}

impl Bundle {
    pub fn from_tar(tar_bytes: &[u8]) -> Result<Self> {
        let mut archive = tar::Archive::new(tar_bytes);
        let mut files = BTreeMap::new();
        for entry in archive.entries().context("reading tar")? {
            let mut entry = entry.context("tar entry")?;
            let kind = entry.header().entry_type();
            if kind.is_dir() {
                continue;
            }
            if !kind.is_file() {
                bail!("bundle contains a non-regular file (links are not allowed)");
            }
            let raw = entry.path().context("tar path")?.to_string_lossy().into_owned();
            let path = normalize_path(&raw).with_context(|| format!("unsafe path in bundle: {raw:?}"))?;
            let mut bytes = Vec::with_capacity(entry.size() as usize);
            entry.read_to_end(&mut bytes)?;
            if files.len() >= MAX_FILES {
                bail!("bundle has more than {MAX_FILES} files");
            }
            let digest = sha256(&bytes);
            let text = as_text(&bytes);
            if files.insert(path.clone(), File { bytes, digest, text }).is_some() {
                bail!("duplicate path in bundle: {path}");
            }
        }
        if files.is_empty() {
            bail!("bundle is empty");
        }
        let mut dirs = BTreeSet::new();
        dirs.insert(String::new());
        for p in files.keys() {
            let mut cur = p.as_str();
            while let Some(i) = cur.rfind('/') {
                cur = &cur[..i];
                if !dirs.insert(cur.to_string()) {
                    break;
                }
            }
        }
        let digests: BTreeMap<String, [u8; 32]> = files.iter().map(|(k, f)| (k.clone(), f.digest)).collect();
        let info = CodeInfo {
            tree_sha256: tree_hash(&digests),
            file_count: files.len() as u64,
            text_file_count: files.values().filter(|f| f.text.is_some()).count() as u64,
            total_bytes: files.values().map(|f| f.bytes.len() as u64).sum(),
        };
        Ok(Self { files, dirs, info })
    }

    pub fn scan_all(&self) -> ScanCounts {
        let mut c = ScanCounts::default();
        for f in self.files.values() {
            if let Some(t) = &f.text {
                scan::add_file(&mut c, t);
            }
        }
        c
    }

    pub fn scan_paths<'a>(&self, paths: impl IntoIterator<Item = &'a String>) -> ScanCounts {
        let mut c = ScanCounts::default();
        for p in paths {
            if let Some(t) = self.files.get(p).and_then(|f| f.text.as_ref()) {
                scan::add_file(&mut c, t);
            }
        }
        c
    }
}

fn clean_dir(p: &str) -> String {
    let p = p.trim().trim_matches('/');
    if p.is_empty() || p == "." {
        return String::new();
    }
    normalize_path(p).unwrap_or_else(|| p.to_string())
}

fn truncate_line(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// Read-only tools. Every call returns text for the model; errors are also
/// returned as text so the model can recover.
pub struct Tools<'a> {
    pub bundle: &'a Bundle,
    pub files_read: BTreeMap<String, [u8; 32]>,
    pub counts: ToolCounts,
}

#[derive(Default)]
pub struct ToolCounts {
    pub list: u32,
    pub find: u32,
    pub read: u32,
    pub grep: u32,
}

const MAX_OUTPUT: usize = 60_000;

impl<'a> Tools<'a> {
    pub fn new(bundle: &'a Bundle) -> Self {
        Self { bundle, files_read: BTreeMap::new(), counts: ToolCounts::default() }
    }

    pub fn call(&mut self, name: &str, args: &serde_json::Value) -> String {
        let r = match name {
            "list_dir" => {
                self.counts.list += 1;
                self.list_dir(args["path"].as_str().unwrap_or(""))
            }
            "find_files" => {
                self.counts.find += 1;
                self.find_files(args["pattern"].as_str().unwrap_or(""), args["max_results"].as_u64())
            }
            "read_file" => {
                self.counts.read += 1;
                self.read_file(
                    args["path"].as_str().unwrap_or(""),
                    args["start_line"].as_u64(),
                    args["end_line"].as_u64(),
                )
            }
            "grep" => {
                self.counts.grep += 1;
                self.grep(
                    args["pattern"].as_str().unwrap_or(""),
                    args["path_prefix"].as_str(),
                    args["case_insensitive"].as_bool().unwrap_or(false),
                    args["max_results"].as_u64(),
                )
            }
            other => Err(anyhow::anyhow!("unknown tool {other}")),
        };
        match r {
            Ok(s) => s,
            Err(e) => format!("error: {e:#}"),
        }
    }

    fn list_dir(&self, path: &str) -> Result<String> {
        let dir = clean_dir(path);
        if !self.bundle.dirs.contains(&dir) {
            bail!("no such directory: {path:?}");
        }
        let prefix = if dir.is_empty() { String::new() } else { format!("{dir}/") };
        let mut out = BTreeSet::new();
        for d in self.bundle.dirs.range(prefix.clone()..) {
            if !d.starts_with(&prefix) {
                break;
            }
            let rest = &d[prefix.len()..];
            if !rest.is_empty() && !rest.contains('/') {
                out.insert(format!("{rest}/"));
            }
        }
        for (p, f) in self.bundle.files.range(prefix.clone()..) {
            if !p.starts_with(&prefix) {
                break;
            }
            let rest = &p[prefix.len()..];
            if !rest.contains('/') {
                out.insert(format!("{rest}  ({} bytes{})", f.bytes.len(), if f.text.is_none() { ", binary" } else { "" }));
            }
        }
        let total = out.len();
        let mut s: String = out.into_iter().take(2000).collect::<Vec<_>>().join("\n");
        if total > 2000 {
            s.push_str(&format!("\n... {} more entries", total - 2000));
        }
        Ok(if s.is_empty() { "(empty)".into() } else { s })
    }

    fn find_files(&self, pattern: &str, max: Option<u64>) -> Result<String> {
        let re = RegexBuilder::new(pattern).size_limit(1 << 20).build().context("invalid regex")?;
        let max = max.unwrap_or(200).min(1000) as usize;
        let hits: Vec<&String> = self.bundle.files.keys().filter(|p| re.is_match(p)).collect();
        let mut s = hits.iter().take(max).map(|p| p.as_str()).collect::<Vec<_>>().join("\n");
        if hits.len() > max {
            s.push_str(&format!("\n... {} more matches", hits.len() - max));
        }
        Ok(if s.is_empty() { "no matching files".into() } else { s })
    }

    fn read_file(&mut self, path: &str, start: Option<u64>, end: Option<u64>) -> Result<String> {
        let path = normalize_path(path.trim()).with_context(|| format!("bad path {path:?}"))?;
        let f = self.bundle.files.get(&path).with_context(|| format!("no such file: {path}"))?;
        let Some(text) = &f.text else {
            return Ok(format!("{path} is a binary file ({} bytes)", f.bytes.len()));
        };
        self.files_read.insert(path.clone(), f.digest);
        let lines: Vec<&str> = text.lines().collect();
        let start = start.unwrap_or(1).max(1) as usize;
        let end = end.map(|e| e as usize).unwrap_or(start + 499).min(lines.len()).min(start + 1999);
        if start > lines.len() {
            return Ok(format!("{path} has only {} lines", lines.len()));
        }
        let mut out = format!("{path} (lines {start}-{end} of {})\n", lines.len());
        for (i, l) in lines[start - 1..end].iter().enumerate() {
            let line = format!("{:>6}\t{}\n", start + i, truncate_line(l, 2000));
            if out.len() + line.len() > MAX_OUTPUT {
                out.push_str(&format!("... output truncated at line {}; request a smaller range\n", start + i));
                break;
            }
            out.push_str(&line);
        }
        Ok(out)
    }

    fn grep(&self, pattern: &str, prefix: Option<&str>, ci: bool, max: Option<u64>) -> Result<String> {
        let re = RegexBuilder::new(pattern)
            .case_insensitive(ci)
            .size_limit(1 << 20)
            .build()
            .context("invalid regex")?;
        let max = max.unwrap_or(100).min(500) as usize;
        let prefix = prefix.map(clean_dir).unwrap_or_default();
        let mut out = Vec::new();
        let mut total = 0usize;
        let mut files_matched = 0usize;
        for (p, f) in self.bundle.files.range(prefix.clone()..) {
            if !p.starts_with(&prefix) {
                break;
            }
            let Some(t) = &f.text else { continue };
            if !re.is_match(t) {
                continue;
            }
            files_matched += 1;
            for (i, l) in t.lines().enumerate() {
                if re.is_match(l) {
                    total += 1;
                    if out.len() < max {
                        out.push(format!("{p}:{}: {}", i + 1, truncate_line(l.trim(), 300)));
                    }
                }
            }
        }
        if out.is_empty() {
            return Ok("no matches".into());
        }
        let mut s = out.join("\n");
        if total > out.len() {
            s.push_str(&format!("\n... {} more matches in {files_matched} files total", total - out.len()));
        }
        Ok(s)
    }
}

pub fn tool_schemas() -> Vec<(&'static str, &'static str, serde_json::Value)> {
    use serde_json::json;
    vec![
        ("list_dir", "List the files and subdirectories of a directory in the repository. Use \"\" for the root.",
            json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]})),
        ("find_files", "Find files whose path matches a regular expression (Rust regex syntax).",
            json!({"type":"object","properties":{"pattern":{"type":"string"},"max_results":{"type":"integer"}},"required":["pattern"]})),
        ("read_file", "Read a range of lines from a text file (default: 500 lines from start_line; at most 2000).",
            json!({"type":"object","properties":{"path":{"type":"string"},"start_line":{"type":"integer"},"end_line":{"type":"integer"}},"required":["path"]})),
        ("grep", "Search file contents line by line with a regular expression (Rust regex syntax). Optionally restrict to a directory prefix.",
            json!({"type":"object","properties":{"pattern":{"type":"string"},"path_prefix":{"type":"string"},"case_insensitive":{"type":"boolean"},"max_results":{"type":"integer"}},"required":["pattern"]})),
        ("submit_verdict", "Finish the audit. Call exactly once.",
            json!({"type":"object","properties":{
                "answer":{"type":"string","enum":["yes","no","inconclusive"]},
                "confidence":{"type":"number","description":"0 to 1"},
                "summary":{"type":"string","description":"For the auditor. Answer the question and explain the basis at a high level. No code, secrets or file contents."}
            },"required":["answer","confidence","summary"]})),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tar_of(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (p, c) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(c.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, p, *c).unwrap();
        }
        b.into_inner().unwrap()
    }

    #[test]
    fn tools_work() {
        let t = tar_of(&[("src/a.rs", b"fn a() {}\n// TODO cot\n"), ("src/b/c.py", b"x = 1\n"), ("bin", b"\0\0")]);
        let b = Bundle::from_tar(&t).unwrap();
        assert_eq!(b.info.file_count, 3);
        let mut tools = Tools::new(&b);
        let l = tools.call("list_dir", &serde_json::json!({"path": "src"}));
        assert!(l.contains("b/") && l.contains("a.rs"), "{l}");
        let g = tools.call("grep", &serde_json::json!({"pattern": "cot"}));
        assert!(g.contains("src/a.rs:2:"), "{g}");
        let r = tools.call("read_file", &serde_json::json!({"path": "src/a.rs"}));
        assert!(r.contains("fn a()"), "{r}");
        assert_eq!(tools.files_read.len(), 1);
        let f = tools.call("find_files", &serde_json::json!({"pattern": "\\.py$"}));
        assert_eq!(f, "src/b/c.py");
        assert!(tools.call("read_file", &serde_json::json!({"path": "../etc/passwd"})).starts_with("error"));
    }

    #[test]
    fn rejects_traversal() {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(1);
        h.set_cksum();
        // Write the raw name to bypass the builder's own path checks.
        h.as_gnu_mut().unwrap().name[..9].copy_from_slice(b"../escape");
        h.set_cksum();
        b.append(&h, &b"x"[..]).unwrap();
        assert!(Bundle::from_tar(&b.into_inner().unwrap()).is_err());
    }
}
