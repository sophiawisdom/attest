//! The auditee's code: an index in enclave memory, contents sealed on the
//! parent (see blobs.rs), plus the read-only tools the model gets over it.
//!
//! Memory use is bounded no matter how large the repository: uploads are
//! parsed as they stream in, one file at a time, and reads go through a
//! shared, size-capped cache.

use crate::blobs::{BlobClient, BlobId, Cache, Sealer, MAX_FILE_BYTES};
use anyhow::{bail, ensure, Context, Result};
use attest_core::tree::{normalize_path, sha256, tree_hash};
use attest_core::{scan, CodeInfo, ScanCounts};
use regex::RegexBuilder;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::sync::Arc;

pub struct Entry {
    blob: BlobId,
    pub size: u64,
    pub digest: [u8; 32],
    pub text: bool,
    /// Instruction-like text found in this file, by category.
    scan: Vec<(&'static str, u64)>,
}

pub struct Bundle {
    pub files: BTreeMap<String, Entry>,
    pub dirs: BTreeSet<String>,
    pub info: CodeInfo,
    scan_total: ScanCounts,
    sealer: Sealer,
    store: BlobClient,
    cache: Arc<Cache>,
}

pub const MAX_FILES: usize = 500_000;

fn is_text(bytes: &[u8]) -> bool {
    !bytes[..bytes.len().min(8192)].contains(&0)
}

impl Bundle {
    /// Parse a tar stream, sealing each file to the parent as it goes.
    /// Blocking: run on a blocking thread. `rt` runs the store calls.
    pub fn ingest<R: Read>(
        reader: R,
        session_id: &str,
        store: BlobClient,
        cache: Arc<Cache>,
        rt: tokio::runtime::Handle,
        max_total: u64,
    ) -> Result<Self> {
        let sealer = Sealer::new(session_id);
        match Self::ingest_inner(reader, &sealer, &store, &rt, max_total) {
            Ok((files, total_scan)) => Ok(Self::finish(files, total_scan, sealer, store, cache)),
            Err(e) => {
                // Don't leave a half-uploaded bundle's blobs behind.
                let _ = rt.block_on(store.delete_session(&sealer.tag));
                Err(e)
            }
        }
    }

    fn ingest_inner<R: Read>(
        reader: R,
        sealer: &Sealer,
        store: &BlobClient,
        rt: &tokio::runtime::Handle,
        max_total: u64,
    ) -> Result<(BTreeMap<String, Entry>, ScanCounts)> {
        let mut archive = tar::Archive::new(reader);
        let mut files = BTreeMap::new();
        let mut total = 0u64;
        let mut scan_total = ScanCounts::default();
        for entry in archive.entries().context("reading tar")? {
            let mut entry = entry.context("tar entry")?;
            let kind = entry.header().entry_type();
            if kind.is_dir() || kind.is_pax_global_extensions() {
                continue;
            }
            if !kind.is_file() {
                bail!("the archive contains a non-regular file (links are not allowed)");
            }
            let raw = entry.path().context("tar path")?.to_string_lossy().into_owned();
            let path = normalize_path(&raw).with_context(|| format!("unsafe path in archive: {raw:?}"))?;
            let size = entry.size();
            ensure!(size as usize <= MAX_FILE_BYTES, "{path} is larger than {} MiB; leave it out", MAX_FILE_BYTES >> 20);
            total += size;
            ensure!(total <= max_total, "the code is larger than {} MiB", max_total >> 20);
            ensure!(files.len() < MAX_FILES, "more than {MAX_FILES} files");
            let mut bytes = Vec::with_capacity(size as usize);
            (&mut entry).take(MAX_FILE_BYTES as u64 + 1).read_to_end(&mut bytes)?;
            ensure!(bytes.len() as u64 == size, "{path}: truncated archive entry");
            let digest = sha256(&bytes);
            let text = is_text(&bytes);
            let scan = if text { scan::scan_text(&String::from_utf8_lossy(&bytes)) } else { vec![] };
            if !scan.is_empty() {
                scan_total.files_with_matches += 1;
                for (k, n) in &scan {
                    *scan_total.matches_by_category.entry(k.to_string()).or_default() += n;
                }
            }
            let (blob, sealed) = sealer.seal(&path, &digest, &bytes)?;
            drop(bytes);
            rt.block_on(store.put(&blob, &sealed)).with_context(|| format!("storing {path}"))?;
            if files.insert(path.clone(), Entry { blob, size, digest, text, scan }).is_some() {
                bail!("duplicate path in archive: {path}");
            }
        }
        ensure!(!files.is_empty(), "the archive is empty");
        Ok((files, scan_total))
    }

    fn finish(files: BTreeMap<String, Entry>, scan_total: ScanCounts, sealer: Sealer, store: BlobClient, cache: Arc<Cache>) -> Self {
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
            text_file_count: files.values().filter(|f| f.text).count() as u64,
            total_bytes: files.values().map(|f| f.size).sum(),
            uploaded_at_ms: attest_core::now_ms(),
        };
        Self { files, dirs, info, scan_total, sealer, store, cache }
    }

    /// Fetch, authenticate and decrypt one file.
    pub async fn read(&self, path: &str) -> Result<Arc<Vec<u8>>> {
        let e = self.files.get(path).with_context(|| format!("no such file: {path}"))?;
        if let Some(hit) = self.cache.get(&e.blob) {
            return Ok(hit);
        }
        let sealed = self.store.get(&e.blob).await?.with_context(|| format!("the host lost the stored copy of {path}"))?;
        let plain = Arc::new(self.sealer.open(path, &e.digest, &sealed)?);
        self.cache.put(e.blob, plain.clone());
        Ok(plain)
    }

    pub fn scan_all(&self) -> ScanCounts {
        self.scan_total.clone()
    }

    pub fn scan_paths<'a>(&self, paths: impl IntoIterator<Item = &'a String>) -> ScanCounts {
        let mut c = ScanCounts::default();
        for p in paths {
            if let Some(e) = self.files.get(p).filter(|e| !e.scan.is_empty()) {
                c.files_with_matches += 1;
                for (k, n) in &e.scan {
                    *c.matches_by_category.entry(k.to_string()).or_default() += n;
                }
            }
        }
        c
    }

    /// Remove this bundle's sealed files from the parent.
    pub async fn discard(&self) {
        self.cache.forget_session(&self.sealer.tag);
        let _ = self.store.delete_session(&self.sealer.tag).await;
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
    pub bundle: &'a Arc<Bundle>,
    pub sandbox: Option<Arc<crate::sandbox::Sandbox>>,
    pub files_read: BTreeMap<String, [u8; 32]>,
    pub counts: ToolCounts,
}

#[derive(Default)]
pub struct ToolCounts {
    pub list: u32,
    pub find: u32,
    pub read: u32,
    pub grep: u32,
    pub python: u32,
}

const MAX_OUTPUT: usize = 60_000;
/// Bytes one grep may scan, so a single call can't take forever.
const MAX_GREP_BYTES: u64 = 2 << 30;

impl<'a> Tools<'a> {
    pub fn new(bundle: &'a Arc<Bundle>, sandbox: Option<Arc<crate::sandbox::Sandbox>>) -> Self {
        Self { bundle, sandbox, files_read: BTreeMap::new(), counts: ToolCounts::default() }
    }

    async fn python(&mut self, code: &str) -> Result<String> {
        let sb = self.sandbox.clone().context("the python sandbox is still starting up; try again in a minute, or use the other tools")?;
        ensure!(!code.trim().is_empty(), "code is empty");
        let opened = Arc::new(std::sync::Mutex::new(BTreeMap::new()));
        let out = sb.run_python(self.bundle.clone(), code, opened.clone()).await;
        self.files_read.extend(opened.lock().unwrap().iter().map(|(k, v)| (k.clone(), *v)));
        let mut s = String::new();
        if out.timed_out {
            s.push_str(&format!("[stopped: the {} s time limit was reached]\n", crate::sandbox::TIME_LIMIT.as_secs()));
        }
        if let Some(e) = &out.error {
            let first: String = e.lines().take(3).collect::<Vec<_>>().join("\n");
            s.push_str(&format!("[sandbox error: {first}]\n"));
        }
        if let Some(c) = out.exit_code {
            if c != 0 {
                s.push_str(&format!("[exit code {c}]\n"));
            }
        }
        if !out.stdout.is_empty() {
            s.push_str(&out.stdout);
            if !out.stdout.ends_with('\n') {
                s.push('\n');
            }
        }
        if !out.stderr.is_empty() {
            s.push_str("--- stderr ---\n");
            s.push_str(&out.stderr);
        }
        if s.is_empty() {
            s.push_str("(no output; use print())");
        }
        Ok(s)
    }

    pub async fn call(&mut self, name: &str, args: &serde_json::Value) -> String {
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
                self.read_file(args["path"].as_str().unwrap_or(""), args["start_line"].as_u64(), args["end_line"].as_u64()).await
            }
            "grep" => {
                self.counts.grep += 1;
                self.grep(
                    args["pattern"].as_str().unwrap_or(""),
                    args["path_prefix"].as_str(),
                    args["case_insensitive"].as_bool().unwrap_or(false),
                    args["max_results"].as_u64(),
                )
                .await
            }
            "python" => {
                self.counts.python += 1;
                self.python(args["code"].as_str().unwrap_or("")).await
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
                out.insert(format!("{rest}  ({} bytes{})", f.size, if f.text { "" } else { ", binary" }));
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

    async fn read_file(&mut self, path: &str, start: Option<u64>, end: Option<u64>) -> Result<String> {
        let path = normalize_path(path.trim()).with_context(|| format!("bad path {path:?}"))?;
        let e = self.bundle.files.get(&path).with_context(|| format!("no such file: {path}"))?;
        if !e.text {
            return Ok(format!("{path} is a binary file ({} bytes)", e.size));
        }
        let digest = e.digest;
        let bytes = self.bundle.read(&path).await?;
        self.files_read.insert(path.clone(), digest);
        let text = String::from_utf8_lossy(&bytes);
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

    async fn grep(&self, pattern: &str, prefix: Option<&str>, ci: bool, max: Option<u64>) -> Result<String> {
        let re = RegexBuilder::new(pattern).case_insensitive(ci).size_limit(1 << 20).build().context("invalid regex")?;
        let max = max.unwrap_or(100).min(500) as usize;
        let prefix = prefix.map(clean_dir).unwrap_or_default();
        let mut out = Vec::new();
        let (mut total, mut files_matched, mut scanned) = (0usize, 0usize, 0u64);
        // Which files to search, within the byte budget.
        let mut targets = Vec::new();
        let mut stopped_early = false;
        for (p, f) in self.bundle.files.range(prefix.clone()..) {
            if !p.starts_with(&prefix) {
                break;
            }
            if !f.text {
                continue;
            }
            if scanned > MAX_GREP_BYTES {
                stopped_early = true;
                break;
            }
            scanned += f.size;
            targets.push(p.clone());
        }
        // Fetch 8 at a time from the parent; results stay in path order.
        use futures_util::StreamExt;
        let mut fetched = futures_util::stream::iter(targets.into_iter().map(|p| async move {
            let r = self.bundle.read(&p).await;
            (p, r)
        }))
        .buffered(8);
        while let Some((p, bytes)) = fetched.next().await {
            let bytes = bytes?;
            let t = String::from_utf8_lossy(&bytes);
            if !re.is_match(&t) {
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
        let mut s = if out.is_empty() { "no matches".to_string() } else { out.join("\n") };
        if total > out.len() {
            s.push_str(&format!("\n... {} more matches in {files_matched} files total", total - out.len()));
        }
        if stopped_early {
            s.push_str("\n(stopped after scanning 2 GiB; narrow the search with path_prefix)");
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
        ("python", "Run a Python 3.15 script in a sandbox and get its printed output. The repository is read-only at /repo (e.g. open('/repo/src/main.py')); the standard library is available, third-party packages are not. No network, no subprocesses, no writing files. Limits per call: 60 s, 512 MiB, 30k characters of output. Use it to parse, count, cross-reference or search in ways the other tools can't.",
            json!({"type":"object","properties":{"code":{"type":"string","description":"Python source to run. print() what you want to see."}},"required":["code"]})),
        ("submit_verdict", "Finish: record your verdict for the auditor (released only if the auditee approves).",
            json!({"type":"object","properties":{
                "answer":{"type":"string","enum":["yes","no","inconclusive","needs_clarification"]},
                "confidence":{"type":"number","description":"0 to 1"},
                "summary":{"type":"string","description":"For the auditor. Answer the question and explain the basis at a high level. No code, secrets or file contents."},
                "clarification_request":{"type":"string","description":"Only with needs_clarification: what the auditor should change about the question."}
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

    fn ingest(t: Vec<u8>, max: u64) -> Result<Bundle> {
        let rt = tokio::runtime::Handle::current();
        let store = BlobClient::memory();
        let cache = Arc::new(Cache::new(1 << 20));
        std::thread::spawn(move || Bundle::ingest(&t[..], "s", store, cache, rt, max)).join().unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn tools_work() {
        let b = Arc::new(ingest(tar_of(&[("src/a.rs", b"fn a() {}\n// TODO cot\n"), ("src/b/c.py", b"x = 1\n"), ("bin", b"\0\0")]), 1 << 30).unwrap());
        assert_eq!(b.info.file_count, 3);
        let mut tools = Tools::new(&b, None);
        let l = tools.call("list_dir", &serde_json::json!({"path": "src"})).await;
        assert!(l.contains("b/") && l.contains("a.rs"), "{l}");
        let g = tools.call("grep", &serde_json::json!({"pattern": "cot"})).await;
        assert!(g.contains("src/a.rs:2:"), "{g}");
        let r = tools.call("read_file", &serde_json::json!({"path": "src/a.rs"})).await;
        assert!(r.contains("fn a()"), "{r}");
        assert_eq!(tools.files_read.len(), 1);
        let f = tools.call("find_files", &serde_json::json!({"pattern": "\\.py$"})).await;
        assert_eq!(f, "src/b/c.py");
        assert!(tools.call("read_file", &serde_json::json!({"path": "../etc/passwd"})).await.starts_with("error"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rejects_traversal() {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(1);
        h.as_gnu_mut().unwrap().name[..9].copy_from_slice(b"../escape");
        h.set_cksum();
        b.append(&h, &b"x"[..]).unwrap();
        assert!(ingest(b.into_inner().unwrap(), 1 << 30).is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn enforces_total_size() {
        let r = ingest(tar_of(&[("a", &[1u8; 600]), ("b", &[1u8; 600])]), 1000);
        assert!(r.err().unwrap().to_string().contains("larger than"));
    }
}
