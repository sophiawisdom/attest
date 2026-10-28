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
    scan: Vec<(String, u64)>,
}

pub struct Bundle {
    pub files: BTreeMap<String, Entry>,
    pub dirs: BTreeSet<String>,
    pub info: CodeInfo,
    scan_total: ScanCounts,
    sealer: Sealer,
    store: BlobClient,
    cache: Arc<Cache>,
    /// While a run is going, every file is held here, so the host sees no
    /// reads that depend on what the model looks at.
    pinned: std::sync::Mutex<(
        usize,
        Option<Arc<std::collections::HashMap<String, Arc<Vec<u8>>>>>,
    )>,
    pin_load: tokio::sync::Mutex<()>,
    /// Hashes of this bundle's manifest record parts once stored (it never
    /// changes, so it's written once; see sessions.rs).
    pub persisted: std::sync::Mutex<Option<Vec<String>>>,
    /// Estimated size of the index above, counted in budget::INDEXES.
    pub index_bytes: usize,
}

/// What a bundle's index takes in memory, roughly: each path, its entry
/// and the tree nodes around it.
fn index_size(files: &BTreeMap<String, Entry>, dirs: &BTreeSet<String>) -> usize {
    let f: usize = files
        .iter()
        .map(|(p, e)| p.len() + 160 + e.scan.iter().map(|(k, _)| k.len() + 40).sum::<usize>())
        .sum();
    let d: usize = dirs.iter().map(|p| p.len() + 64).sum();
    let n = f + d;
    crate::budget::add(&crate::budget::INDEXES, n);
    n
}

/// Everything needed to rebuild a Bundle in a successor enclave: the index,
/// and the sealing key of its stored files.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct CodeManifest {
    files: Vec<(String, ManifestEntry)>,
    dirs: Vec<String>,
    info: CodeInfo,
    scan_total: ScanCounts,
    key: String,
    tag: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ManifestEntry {
    blob: String,
    size: u64,
    digest: String,
    text: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    scan: Vec<(String, u64)>,
}

/// Keeps a bundle's files in enclave memory until dropped.
pub struct Pin(Arc<Bundle>);

impl Drop for Pin {
    fn drop(&mut self) {
        let mut g = self.0.pinned.lock().unwrap();
        g.0 -= 1;
        if g.0 == 0 {
            g.1 = None;
        }
    }
}

pub const MAX_FILES: usize = 500_000;

/// Lines `start..=end` (1-based, model-chosen) of `text`, numbered. Any
/// numbers are accepted: out-of-range or reversed ranges get a message, not
/// a panic, and no per-line index of the whole file is built.
fn select_lines(path: &str, text: &str, start: Option<u64>, end: Option<u64>) -> String {
    let total = text.lines().count() as u64;
    let start = start.unwrap_or(1).max(1);
    if start > total {
        return format!("{path} has only {total} lines");
    }
    let end = end
        .unwrap_or(start.saturating_add(499))
        .min(total)
        .min(start.saturating_add(1999));
    if end < start {
        return format!("{path}: end_line {end} is before start_line {start}");
    }
    let mut out = format!("{path} (lines {start}-{end} of {total})\n");
    let skip = (start - 1) as usize;
    let take = (end - start + 1) as usize;
    for (i, l) in text.lines().skip(skip).take(take).enumerate() {
        let n = start + i as u64;
        let line = format!("{n:>6}\t{}\n", truncate_line(l, 2000));
        if out.len() + line.len() > MAX_OUTPUT {
            out.push_str(&format!(
                "... output truncated at line {n}; request a smaller range\n"
            ));
            break;
        }
        out.push_str(&line);
    }
    out
}
/// Archive metadata limits, checked as entries stream in, so a tiny archive
/// can't make the enclave build huge path or directory indexes.
pub const MAX_PATH_BYTES: usize = 1024;
pub const MAX_PATH_DEPTH: usize = 48;
pub const MAX_DIRS: usize = 200_000;
/// Sum of all path lengths.
pub const MAX_PATH_TOTAL: usize = 64 << 20;
/// Size of a GNU long-name or PAX extension record.
const MAX_EXT_RECORD: u64 = 64 << 10;

/// The `path` value of a PAX extended header, if it has one.
fn pax_path(rec: &[u8]) -> Result<Option<String>> {
    let mut rest = rec;
    let mut path = None;
    while !rest.is_empty() {
        let sp = rest
            .iter()
            .position(|&b| b == b' ')
            .context("malformed PAX record")?;
        let len: usize = std::str::from_utf8(&rest[..sp])
            .ok()
            .and_then(|n| n.parse().ok())
            .context("malformed PAX record length")?;
        ensure!(len > sp + 1 && len <= rest.len(), "malformed PAX record");
        let kv = &rest[sp + 1..len];
        let kv = kv.strip_suffix(b"\n").unwrap_or(kv);
        if let Some(v) = kv.strip_prefix(b"path=") {
            path = Some(String::from_utf8_lossy(v).into_owned());
        }
        rest = &rest[len..];
    }
    Ok(path)
}

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
        strip_top: bool,
    ) -> Result<Self> {
        let sealer = Sealer::new(session_id);
        match Self::ingest_inner(reader, &sealer, &store, &rt, max_total, strip_top) {
            Ok((files, total_scan, dirs)) => {
                Ok(Self::finish(files, dirs, total_scan, sealer, store, cache))
            }
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
        strip_top: bool,
    ) -> Result<(BTreeMap<String, Entry>, ScanCounts, BTreeSet<String>)> {
        let mut archive = tar::Archive::new(reader);
        let mut files = BTreeMap::new();
        let mut dirs = BTreeSet::new();
        dirs.insert(String::new());
        let mut total = 0u64;
        let mut path_total = 0usize;
        let mut scan_total = ScanCounts::default();
        // Raw entries: GNU long names and PAX headers reach us as entries,
        // so their size is checked before anything is buffered.
        let mut long_name: Option<String> = None;
        for entry in archive.entries().context("reading tar")?.raw(true) {
            let mut entry = entry.context("tar entry")?;
            let kind = entry.header().entry_type();
            if kind.is_gnu_longname()
                || kind.is_pax_local_extensions()
                || kind.is_pax_global_extensions()
            {
                ensure!(
                    entry.size() <= MAX_EXT_RECORD,
                    "an archive header record is too large"
                );
                let mut rec = Vec::new();
                (&mut entry).take(MAX_EXT_RECORD).read_to_end(&mut rec)?;
                if kind.is_gnu_longname() {
                    let end = rec.iter().position(|&b| b == 0).unwrap_or(rec.len());
                    long_name = Some(String::from_utf8_lossy(&rec[..end]).into_owned());
                } else if kind.is_pax_local_extensions() {
                    if let Some(p) = pax_path(&rec)? {
                        long_name = Some(p);
                    }
                }
                continue;
            }
            let name = long_name.take();
            if kind.is_dir() {
                continue;
            }
            if !kind.is_file() {
                bail!("the archive contains a non-regular file (links are not allowed)");
            }
            let raw = match name {
                Some(n) => n,
                None => entry
                    .path()
                    .context("tar path")?
                    .to_string_lossy()
                    .into_owned(),
            };
            // A GitHub archive puts everything under one "owner-repo-sha/".
            let raw = if strip_top {
                match raw.split_once('/') {
                    Some((_, rest)) if !rest.is_empty() => rest.to_string(),
                    _ => continue,
                }
            } else {
                raw
            };
            ensure!(
                raw.len() <= MAX_PATH_BYTES,
                "a path is longer than {MAX_PATH_BYTES} bytes"
            );
            let path =
                normalize_path(&raw).with_context(|| format!("unsafe path in archive: {raw:?}"))?;
            ensure!(
                path.split('/').count() <= MAX_PATH_DEPTH,
                "{path} is nested more than {MAX_PATH_DEPTH} levels deep"
            );
            path_total += path.len();
            ensure!(
                path_total <= MAX_PATH_TOTAL,
                "the archive's paths are too long in total"
            );
            let mut cur = path.as_str();
            while let Some(i) = cur.rfind('/') {
                cur = &cur[..i];
                if !dirs.insert(cur.to_string()) {
                    break;
                }
            }
            ensure!(dirs.len() <= MAX_DIRS, "more than {MAX_DIRS} directories");
            let size = entry.size();
            ensure!(
                size as usize <= MAX_FILE_BYTES,
                "{path} is larger than {} MiB; leave it out",
                MAX_FILE_BYTES >> 20
            );
            total += size;
            ensure!(
                total <= max_total,
                "the code is larger than {} MiB",
                max_total >> 20
            );
            ensure!(files.len() < MAX_FILES, "more than {MAX_FILES} files");
            let mut bytes = Vec::with_capacity(size as usize);
            (&mut entry)
                .take(MAX_FILE_BYTES as u64 + 1)
                .read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() as u64 == size,
                "{path}: truncated archive entry"
            );
            let digest = sha256(&bytes);
            let text = is_text(&bytes);
            let scan = if text {
                scan::scan_text(&String::from_utf8_lossy(&bytes))
                    .into_iter()
                    .map(|(k, n)| (k.to_string(), n))
                    .collect()
            } else {
                vec![]
            };
            if !scan.is_empty() {
                scan_total.files_with_matches += 1;
                for (k, n) in &scan {
                    *scan_total
                        .matches_by_category
                        .entry(k.to_string())
                        .or_default() += n;
                }
            }
            let (blob, sealed) = sealer.seal(&path, &digest, &bytes)?;
            drop(bytes);
            rt.block_on(store.put(&blob, &sealed))
                .with_context(|| format!("storing {path}"))?;
            if files
                .insert(
                    path.clone(),
                    Entry {
                        blob,
                        size,
                        digest,
                        text,
                        scan,
                    },
                )
                .is_some()
            {
                bail!("duplicate path in archive: {path}");
            }
        }
        ensure!(!files.is_empty(), "the archive is empty");
        Ok((files, scan_total, dirs))
    }

    fn finish(
        files: BTreeMap<String, Entry>,
        dirs: BTreeSet<String>,
        scan_total: ScanCounts,
        sealer: Sealer,
        store: BlobClient,
        cache: Arc<Cache>,
    ) -> Self {
        let index_bytes = index_size(&files, &dirs);
        let digests: BTreeMap<String, [u8; 32]> =
            files.iter().map(|(k, f)| (k.clone(), f.digest)).collect();
        let tree = tree_hash(&digests);
        let mut salt = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
        let salt = hex::encode(salt);
        let info = CodeInfo {
            commitment_sha256: attest_core::code_commitment(&salt, &tree),
            commitment_salt: salt,
            tree_sha256: tree,
            file_count: files.len() as u64,
            text_file_count: files.values().filter(|f| f.text).count() as u64,
            total_bytes: files.values().map(|f| f.size).sum(),
            uploaded_at_ms: attest_core::now_ms(),
        };
        Self {
            files,
            dirs,
            info,
            scan_total,
            sealer,
            store,
            cache,
            pinned: Default::default(),
            pin_load: Default::default(),
            persisted: Default::default(),
            index_bytes,
        }
    }

    /// The record a successor rebuilds this bundle from.
    pub fn manifest(&self) -> CodeManifest {
        CodeManifest {
            files: self
                .files
                .iter()
                .map(|(p, e)| {
                    (
                        p.clone(),
                        ManifestEntry {
                            blob: hex::encode(e.blob),
                            size: e.size,
                            digest: hex::encode(e.digest),
                            text: e.text,
                            scan: e.scan.clone(),
                        },
                    )
                })
                .collect(),
            dirs: self.dirs.iter().cloned().collect(),
            info: self.info.clone(),
            scan_total: self.scan_total.clone(),
            key: hex::encode(self.sealer.key()),
            tag: hex::encode(self.sealer.tag),
        }
    }

    /// Rebuild a bundle from its manifest; its files stay where they are.
    pub fn restore(session_id: &str, m: CodeManifest, store: BlobClient, cache: Arc<Cache>) -> Result<Self> {
        fn arr<const N: usize>(h: &str) -> Result<[u8; N]> {
            hex::decode(h)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("bad length in a code manifest"))
        }
        let mut files = BTreeMap::new();
        for (p, e) in m.files {
            files.insert(
                p,
                Entry {
                    blob: arr(&e.blob)?,
                    size: e.size,
                    digest: arr(&e.digest)?,
                    text: e.text,
                    scan: e.scan,
                },
            );
        }
        let dirs = m.dirs.into_iter().collect();
        let sealer = Sealer::from_parts(session_id, arr(&m.key)?, arr(&m.tag)?);
        let index_bytes = index_size(&files, &dirs);
        Ok(Self {
            files,
            dirs,
            info: m.info,
            scan_total: m.scan_total,
            sealer,
            store,
            cache,
            pinned: Default::default(),
            pin_load: Default::default(),
            persisted: Default::default(),
            index_bytes,
        })
    }

    /// Load every file into enclave memory, in path order and without the
    /// shared cache, so the host sees the same reads whatever the run does
    /// later. Reads go only to memory while the returned Pin lives.
    pub async fn pin(self: &Arc<Self>) -> Result<Pin> {
        let _loading = self.pin_load.lock().await;
        {
            let mut g = self.pinned.lock().unwrap();
            if g.1.is_some() {
                g.0 += 1;
                return Ok(Pin(self.clone()));
            }
        }
        use futures_util::StreamExt;
        let mut all = std::collections::HashMap::with_capacity(self.files.len());
        let jobs: Vec<(String, BlobId, [u8; 32])> = self
            .files
            .iter()
            .map(|(p, e)| (p.clone(), e.blob, e.digest))
            .collect();
        let mut fetched = futures_util::stream::iter(jobs.into_iter().map(|(p, blob, digest)| {
            let me = self.clone();
            async move {
                let sealed = me
                    .store
                    .get(&blob)
                    .await?
                    .with_context(|| format!("the host lost the stored copy of {p}"))?;
                let plain = me.sealer.open(&p, &digest, &sealed)?;
                Ok::<_, anyhow::Error>((p, Arc::new(plain)))
            }
        }))
        .buffered(8);
        while let Some(r) = fetched.next().await {
            let (p, data) = r?;
            all.insert(p, data);
        }
        let mut g = self.pinned.lock().unwrap();
        g.0 += 1;
        g.1 = Some(Arc::new(all));
        Ok(Pin(self.clone()))
    }

    /// Fetch, authenticate and decrypt one file.
    pub async fn read(&self, path: &str) -> Result<Arc<Vec<u8>>> {
        let e = self
            .files
            .get(path)
            .with_context(|| format!("no such file: {path}"))?;
        if let Some(all) = self.pinned.lock().unwrap().1.clone() {
            return all
                .get(path)
                .cloned()
                .with_context(|| format!("no such file: {path}"));
        }
        if let Some(hit) = self.cache.get(&e.blob) {
            return Ok(hit);
        }
        let sealed = self
            .store
            .get(&e.blob)
            .await?
            .with_context(|| format!("the host lost the stored copy of {path}"))?;
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
                    *c.matches_by_category.entry(k.clone()).or_default() += n;
                }
            }
        }
        c
    }
}

/// The stored files go when the last user of the code does (the session,
/// a run, a disclosure), after a delay (see BlobClient::delete_later).
impl Drop for Bundle {
    fn drop(&mut self) {
        self.cache.forget_session(&self.sealer.tag);
        self.store.delete_later(self.sealer.tag);
        crate::budget::sub(&crate::budget::INDEXES, self.index_bytes);
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
        Self {
            bundle,
            sandbox,
            files_read: BTreeMap::new(),
            counts: ToolCounts::default(),
        }
    }

    async fn python(&mut self, code: &str) -> Result<String> {
        let sb = self.sandbox.clone().context("the python sandbox is still starting up; try again in a minute, or use the other tools")?;
        ensure!(!code.trim().is_empty(), "code is empty");
        let opened = Arc::new(std::sync::Mutex::new(BTreeMap::new()));
        let out = sb
            .run_python(self.bundle.clone(), code, opened.clone())
            .await;
        self.files_read
            .extend(opened.lock().unwrap().iter().map(|(k, v)| (k.clone(), *v)));
        let mut s = String::new();
        if out.timed_out {
            s.push_str(&format!(
                "[stopped: the {} s time limit was reached]\n",
                crate::sandbox::TIME_LIMIT.as_secs()
            ));
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
                self.find_files(
                    args["pattern"].as_str().unwrap_or(""),
                    args["max_results"].as_u64(),
                )
            }
            "read_file" => {
                self.counts.read += 1;
                self.read_file(
                    args["path"].as_str().unwrap_or(""),
                    args["start_line"].as_u64(),
                    args["end_line"].as_u64(),
                )
                .await
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
        let prefix = if dir.is_empty() {
            String::new()
        } else {
            format!("{dir}/")
        };
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
                out.insert(format!(
                    "{rest}  ({} bytes{})",
                    f.size,
                    if f.text { "" } else { ", binary" }
                ));
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
        let re = RegexBuilder::new(pattern)
            .size_limit(1 << 20)
            .build()
            .context("invalid regex")?;
        let max = max.unwrap_or(200).min(1000) as usize;
        let hits: Vec<&String> = self
            .bundle
            .files
            .keys()
            .filter(|p| re.is_match(p))
            .collect();
        let mut s = hits
            .iter()
            .take(max)
            .map(|p| p.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        if hits.len() > max {
            s.push_str(&format!("\n... {} more matches", hits.len() - max));
        }
        Ok(if s.is_empty() {
            "no matching files".into()
        } else {
            s
        })
    }

    async fn read_file(
        &mut self,
        path: &str,
        start: Option<u64>,
        end: Option<u64>,
    ) -> Result<String> {
        let path = normalize_path(path.trim()).with_context(|| format!("bad path {path:?}"))?;
        let e = self
            .bundle
            .files
            .get(&path)
            .with_context(|| format!("no such file: {path}"))?;
        if !e.text {
            return Ok(format!("{path} is a binary file ({} bytes)", e.size));
        }
        let digest = e.digest;
        let bytes = self.bundle.read(&path).await?;
        self.files_read.insert(path.clone(), digest);
        // Off the async workers: a large file takes a while to scan.
        tokio::task::spawn_blocking(move || {
            select_lines(&path, &String::from_utf8_lossy(&bytes), start, end)
        })
        .await
        .context("reading the file")
    }

    async fn grep(
        &self,
        pattern: &str,
        prefix: Option<&str>,
        ci: bool,
        max: Option<u64>,
    ) -> Result<String> {
        let re = RegexBuilder::new(pattern)
            .case_insensitive(ci)
            .size_limit(1 << 20)
            .build()
            .context("invalid regex")?;
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
        // Matching lines of one file, up to `room` of them, plus the count.
        fn scan(re: &regex::Regex, p: &str, bytes: &[u8], room: usize) -> (usize, Vec<String>) {
            let t = String::from_utf8_lossy(bytes);
            if !re.is_match(&t) {
                return (0, vec![]);
            }
            let (mut n, mut hits) = (0, vec![]);
            for (i, l) in t.lines().enumerate() {
                if re.is_match(l) {
                    n += 1;
                    if hits.len() < room {
                        hits.push(format!("{p}:{}: {}", i + 1, truncate_line(l.trim(), 300)));
                    }
                }
            }
            (n, hits)
        }
        while let Some((p, bytes)) = fetched.next().await {
            let bytes = bytes?;
            let room = max - out.len();
            // Big files are matched off the async workers, which the HTTP
            // server shares.
            let (n, hits) = if bytes.len() > 64 << 10 {
                let re = re.clone();
                tokio::task::spawn_blocking(move || scan(&re, &p, &bytes, room))
                    .await
                    .context("grep")?
            } else {
                scan(&re, &p, &bytes, room)
            };
            if n > 0 {
                files_matched += 1;
                total += n;
                out.extend(hits);
            }
        }
        let mut s = if out.is_empty() {
            "no matches".to_string()
        } else {
            out.join("\n")
        };
        if total > out.len() {
            s.push_str(&format!(
                "\n... {} more matches in {files_matched} files total",
                total - out.len()
            ));
        }
        if stopped_early {
            s.push_str("\n(stopped after scanning 2 GiB; narrow the search with path_prefix)");
        }
        Ok(s)
    }
}

/// The verdict tool, narrowed to the agreed answer format.
fn verdict_schema(format: &attest_core::AnswerFormat) -> serde_json::Value {
    use attest_core::AnswerFormat;
    use serde_json::json;
    match format {
        AnswerFormat::YesNo => json!({"type":"object","properties":{
            "answer":{"type":"string","enum":["yes","no","inconclusive"]}
        },"required":["answer"]}),
        AnswerFormat::Choice { options } => json!({"type":"object","properties":{
            "choice":{"type":"string","enum": options}
        },"required":["choice"]}),
        AnswerFormat::Text { max_bytes } => json!({"type":"object","properties":{
            "answer":{"type":"string","enum":["yes","no","inconclusive","needs_clarification"]},
            "confidence":{"type":"number","description":"0 to 1"},
            "summary":{"type":"string","description": format!("For the auditor, at most {max_bytes} bytes. Answer the question and explain the basis at a high level. No code, secrets or file contents.")},
            "clarification_request":{"type":"string","description":"Only with needs_clarification: what the auditor should change about the question (counts toward the byte limit)."}
        },"required":["answer","confidence","summary"]}),
    }
}

pub fn tool_schemas(
    format: &attest_core::AnswerFormat,
) -> Vec<(&'static str, &'static str, serde_json::Value)> {
    let mut v = base_tool_schemas();
    v.push(("submit_verdict", "Finish: record your verdict for the auditor (released only if the auditee approves). It must fit the agreed answer format.", verdict_schema(format)));
    v
}

fn base_tool_schemas() -> Vec<(&'static str, &'static str, serde_json::Value)> {
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
        std::thread::spawn(move || Bundle::ingest(&t[..], "s", store, cache, rt, max, false))
            .join()
            .unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn tools_work() {
        let b = Arc::new(
            ingest(
                tar_of(&[
                    ("src/a.rs", b"fn a() {}\n// TODO cot\n"),
                    ("src/b/c.py", b"x = 1\n"),
                    ("bin", b"\0\0"),
                ]),
                1 << 30,
            )
            .unwrap(),
        );
        assert_eq!(b.info.file_count, 3);
        let mut tools = Tools::new(&b, None);
        let l = tools
            .call("list_dir", &serde_json::json!({"path": "src"}))
            .await;
        assert!(l.contains("b/") && l.contains("a.rs"), "{l}");
        let g = tools
            .call("grep", &serde_json::json!({"pattern": "cot"}))
            .await;
        assert!(g.contains("src/a.rs:2:"), "{g}");
        let r = tools
            .call("read_file", &serde_json::json!({"path": "src/a.rs"}))
            .await;
        assert!(r.contains("fn a()"), "{r}");
        assert_eq!(tools.files_read.len(), 1);
        let f = tools
            .call("find_files", &serde_json::json!({"pattern": "\\.py$"}))
            .await;
        assert_eq!(f, "src/b/c.py");
        assert!(tools
            .call("read_file", &serde_json::json!({"path": "../etc/passwd"}))
            .await
            .starts_with("error"));
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
    async fn stored_files_go_with_the_last_user() {
        let store = BlobClient::memory();
        let rt = tokio::runtime::Handle::current();
        let s2 = store.clone();
        let t = tar_of(&[("a", b"x")]);
        let b = Arc::new(
            std::thread::spawn(move || {
                Bundle::ingest(&t[..], "s", s2, Arc::new(Cache::new(1 << 20)), rt, 1 << 20, false)
            })
            .join()
            .unwrap()
            .unwrap(),
        );
        let blob = b.files["a"].blob;
        let run = b.clone(); // a run still holding the code
        drop(b);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(store.get(&blob).await.unwrap().is_some());
        drop(run);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(store.get(&blob).await.unwrap().is_none());
    }

    #[test]
    fn line_ranges_never_panic() {
        let t = "a\nb\nc\nd\n";
        assert!(select_lines("f", t, Some(3), Some(1)).contains("before"));
        assert!(select_lines("f", t, Some(u64::MAX), None).contains("only 4 lines"));
        assert!(select_lines("f", t, Some(2), Some(u64::MAX)).contains("lines 2-4 of 4"));
        assert!(select_lines("f", t, Some(0), Some(0)).contains("before"));
        assert!(select_lines("f", "", None, None).contains("only 0 lines"));
        let r = select_lines("f", t, Some(2), Some(3));
        assert!(r.contains("     2\tb") && r.contains("     3\tc") && !r.contains("\td"), "{r}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn long_paths_and_metadata_limits() {
        // A long name (GNU long-name record) is accepted...
        let long = format!("{}/x.rs", "d".repeat(200));
        let b = ingest(tar_of(&[(long.as_str(), b"ok")]), 1 << 30).unwrap();
        assert!(b.files.contains_key(&long));
        // ...but too long, or too deep, is refused.
        let too_long = "a".repeat(MAX_PATH_BYTES + 1);
        assert!(ingest(tar_of(&[(too_long.as_str(), b"x")]), 1 << 30).is_err());
        let deep = vec!["a"; MAX_PATH_DEPTH + 1].join("/");
        assert!(ingest(tar_of(&[(deep.as_str(), b"x")]), 1 << 30).is_err());
        // PAX path records parse.
        assert_eq!(
            pax_path(b"21 path=some/file.rs\n").unwrap().as_deref(),
            Some("some/file.rs")
        );
        assert!(pax_path(b"99 path=x\n").is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn enforces_total_size() {
        let r = ingest(tar_of(&[("a", &[1u8; 600]), ("b", &[1u8; 600])]), 1000);
        assert!(r.err().unwrap().to_string().contains("larger than"));
    }
}
