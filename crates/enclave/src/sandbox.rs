//! A Python sandbox for the agent: CPython compiled to WebAssembly (WASI),
//! run by wasmtime inside the enclave process.
//!
//! The guest sees two read-only directories: the repository at /repo
//! (served from the sealed store, see bundle.rs) and the Python standard
//! library. WASI gives it no sockets, no subprocesses, no devices and no
//! writable files, so there is nothing to block: it can compute and print,
//! and its output goes back to the model (which the auditee watches).
//! Memory and CPU time are capped per call.

use crate::bundle::Bundle;
use anyhow::{anyhow, Context, Result};
use std::any::Any;
use std::collections::BTreeMap;
use std::io::{IoSliceMut, SeekFrom, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use wasi_common::dir::{OpenResult, ReaddirCursor, ReaddirEntity};
use wasi_common::file::{FdFlags, FileType, Filestat, OFlags};
use wasi_common::{Error, ErrorExt, WasiCtx, WasiDir, WasiFile};
use wasmtime::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};

pub const MEMORY_LIMIT: usize = 512 << 20;
pub const TIME_LIMIT: Duration = Duration::from_secs(60);
const OUTPUT_LIMIT: usize = 30_000;
const TICK: Duration = Duration::from_millis(100);
/// Opens and directory-listing work one invocation may cause; see RoDir::charge.
const HOST_WORK_BUDGET: u64 = 2_000_000;

pub struct Sandbox {
    engine: Engine,
    module: Module,
    /// The Python standard library, loaded into memory once and served
    /// read-only (shared by every session, so it must be immutable).
    stdlib: Arc<StaticTree>,
}

/// An immutable in-memory directory tree.
pub struct StaticTree {
    files: BTreeMap<String, Arc<Vec<u8>>>,
    dirs: std::collections::BTreeSet<String>,
}

impl StaticTree {
    fn load(root: &Path) -> Result<Self> {
        let mut files = BTreeMap::new();
        let mut dirs = std::collections::BTreeSet::new();
        dirs.insert(String::new());
        let mut stack = vec![root.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d)? {
                let e = e?;
                let rel = e.path().strip_prefix(root)?.to_string_lossy().into_owned();
                let ft = e.file_type()?;
                if ft.is_dir() {
                    dirs.insert(rel);
                    stack.push(e.path());
                } else if ft.is_file() {
                    files.insert(rel, Arc::new(std::fs::read(e.path())?));
                }
            }
        }
        Ok(Self { files, dirs })
    }
}

/// What a read-only guest directory is backed by.
#[derive(Clone)]
enum Source {
    Repo(Arc<Bundle>),
    Static(Arc<StaticTree>),
}

impl Source {
    fn is_dir(&self, p: &str) -> bool {
        match self {
            Source::Repo(b) => b.dirs.contains(p),
            Source::Static(t) => t.dirs.contains(p),
        }
    }
    fn file(&self, p: &str) -> Option<(u64, [u8; 32])> {
        match self {
            Source::Repo(b) => b.files.get(p).map(|e| (e.size, e.digest)),
            Source::Static(t) => t.files.get(p).map(|f| (f.len() as u64, [0u8; 32])),
        }
    }
    async fn read(&self, p: &str) -> Result<Arc<Vec<u8>>, Error> {
        match self {
            Source::Repo(b) => b.read(p).await.map_err(|_| Error::io()),
            Source::Static(t) => t.files.get(p).cloned().ok_or_else(Error::not_found),
        }
    }
    fn children(&self, prefix: &str) -> Vec<(String, FileType)> {
        let mut out = Vec::new();
        let (dirs, files): (
            Box<dyn Iterator<Item = &String>>,
            Box<dyn Iterator<Item = &String>>,
        ) = match self {
            Source::Repo(b) => (
                Box::new(b.dirs.range(prefix.to_string()..)),
                Box::new(b.files.range(prefix.to_string()..).map(|(k, _)| k)),
            ),
            Source::Static(t) => (
                Box::new(t.dirs.range(prefix.to_string()..)),
                Box::new(t.files.range(prefix.to_string()..).map(|(k, _)| k)),
            ),
        };
        for d in dirs.take_while(|d| d.starts_with(prefix)) {
            let rest = &d[prefix.len()..];
            if !rest.is_empty() && !rest.contains('/') {
                out.push((rest.to_string(), FileType::Directory));
            }
        }
        for p in files.take_while(|p| p.starts_with(prefix)) {
            let rest = &p[prefix.len()..];
            if !rest.contains('/') {
                out.push((rest.to_string(), FileType::RegularFile));
            }
        }
        out
    }
}

pub struct Output {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub error: Option<String>,
}

struct GuestState {
    wasi: WasiCtx,
    limits: StoreLimits,
}

impl Sandbox {
    /// Compile python.wasm from `dir` (blocking; takes a while).
    pub fn load(dir: &Path) -> Result<Self> {
        let mut config = Config::new();
        config.epoch_interruption(true);
        // Bounds-checked memories with small reservations: the enclave has
        // no swap and a fixed RAM budget.
        config.memory_reservation(0);
        config.memory_guard_size(64 << 10);
        config.memory_may_move(true);
        let engine = Engine::new(&config).map_err(|e| anyhow!("wasm engine: {e}"))?;
        let wasm = std::fs::read(dir.join("python.wasm"))
            .with_context(|| format!("reading {}/python.wasm", dir.display()))?;
        let module =
            Module::new(&engine, &wasm).map_err(|e| anyhow!("compiling python.wasm: {e}"))?;
        let stdlib = Arc::new(
            StaticTree::load(&dir.join("lib")).context("loading the Python standard library")?,
        );
        // One ticker for the engine; per-call deadlines count ticks.
        let ticker = engine.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(TICK);
            ticker.increment_epoch();
        });
        Ok(Self {
            engine,
            module,
            stdlib,
        })
    }

    pub async fn run_python(
        &self,
        bundle: Arc<Bundle>,
        code: &str,
        opened: Arc<Mutex<BTreeMap<String, [u8; 32]>>>,
    ) -> Output {
        self.run_python_within(bundle, code, opened, TIME_LIMIT).await
    }

    async fn run_python_within(
        &self,
        bundle: Arc<Bundle>,
        code: &str,
        opened: Arc<Mutex<BTreeMap<String, [u8; 32]>>>,
        limit: Duration,
    ) -> Output {
        let stdout = Capped::default();
        let stderr = Capped::default();
        // Wall-clock limit for everything, including time the guest spends
        // in host calls such as sleep(), which epoch checks don't see. The
        // guest yields every tick (see run_inner), so this fires on time
        // and dropping the future cancels whatever it was doing.
        let result = tokio::time::timeout(
            limit,
            self.run_inner(bundle, code, opened, stdout.clone(), stderr.clone()),
        )
        .await;
        let (exit_code, timed_out, error) = match result {
            Err(_) => (None, true, None),
            Ok(Ok(code)) => (Some(code), false, None),
            Ok(Err(e)) => {
                let msg = format!("{e:#}");
                let timed_out = msg.contains("interrupt") || msg.contains("epoch");
                (None, timed_out, if timed_out { None } else { Some(msg) })
            }
        };
        Output {
            stdout: stdout.text(),
            stderr: stderr.text(),
            exit_code,
            timed_out,
            error,
        }
    }

    async fn run_inner(
        &self,
        bundle: Arc<Bundle>,
        code: &str,
        opened: Arc<Mutex<BTreeMap<String, [u8; 32]>>>,
        stdout: Capped,
        stderr: Capped,
    ) -> Result<i32> {
        let mut b = wasi_common::tokio::WasiCtxBuilder::new();
        b.args(&[
            "python".into(),
            "-I".into(),
            "-B".into(),
            "-c".into(),
            code.into(),
        ])
        .map_err(|e| anyhow!("{e}"))?;
        b.env("PYTHONIOENCODING", "utf-8")
            .map_err(|e| anyhow!("{e}"))?;
        b.env("PYTHONDONTWRITEBYTECODE", "1")
            .map_err(|e| anyhow!("{e}"))?;
        b.stdout(Box::new(wasi_common::pipe::WritePipe::new(stdout)));
        b.stderr(Box::new(wasi_common::pipe::WritePipe::new(stderr)));
        let wasi = b.build();
        // Both directories are read-only views of immutable data; nothing in
        // the guest can write anywhere. They share one work budget.
        let budget = Arc::new(std::sync::atomic::AtomicU64::new(HOST_WORK_BUDGET));
        wasi.push_preopened_dir(
            Box::new(RoDir {
                source: Source::Static(self.stdlib.clone()),
                prefix: String::new(),
                opened: None,
                budget: budget.clone(),
            }),
            "/usr/local/lib",
        )
        .map_err(|e| anyhow!("{e}"))?;
        wasi.push_preopened_dir(
            Box::new(RoDir {
                source: Source::Repo(bundle),
                prefix: String::new(),
                opened: Some(opened),
                budget,
            }),
            "/repo",
        )
        .map_err(|e| anyhow!("{e}"))?;

        let limits = StoreLimitsBuilder::new()
            .memory_size(MEMORY_LIMIT)
            .instances(4)
            .tables(64)
            .memories(4)
            .build();
        let mut store = Store::new(&self.engine, GuestState { wasi, limits });
        store.limiter(|s| &mut s.limits);
        // Yield to the async runtime every tick, so a busy guest can't hold
        // a worker thread (the HTTP server shares them); the overall limit
        // is the timeout in run_python.
        store.set_epoch_deadline(1);
        store.epoch_deadline_async_yield_and_update(1);
        let mut linker: Linker<GuestState> = Linker::new(&self.engine);
        wasi_common::tokio::add_to_linker(&mut linker, |s| &mut s.wasi)
            .map_err(|e| anyhow!("{e}"))?;
        linker
            .module_async(&mut store, "", &self.module)
            .await
            .map_err(|e| anyhow!("{e}"))?;
        let start = linker
            .get_default(&mut store, "")
            .map_err(|e| anyhow!("{e}"))?
            .typed::<(), ()>(&store)
            .map_err(|e| anyhow!("{e}"))?;
        match start.call_async(&mut store, ()).await {
            Ok(()) => Ok(0),
            Err(e) => match e.downcast_ref::<wasi_common::I32Exit>() {
                Some(exit) => Ok(exit.0),
                None => Err(anyhow!("{e:?}")),
            },
        }
    }
}

/// Output buffer that keeps at most OUTPUT_LIMIT bytes.
#[derive(Clone, Default)]
struct Capped(Arc<Mutex<(Vec<u8>, usize)>>);

impl Capped {
    fn text(&self) -> String {
        let g = self.0.lock().unwrap();
        let mut s = String::from_utf8_lossy(&g.0).into_owned();
        if g.1 > g.0.len() {
            s.push_str(&format!(
                "\n[... {} more bytes of output not shown]",
                g.1 - g.0.len()
            ));
        }
        s
    }
}

impl Write for Capped {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut g = self.0.lock().unwrap();
        g.1 += buf.len();
        let room = OUTPUT_LIMIT.saturating_sub(g.0.len());
        let n = room.min(buf.len());
        g.0.extend_from_slice(&buf[..n]);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// ------------------------------------------------------------------ /repo

fn inode(path: &str) -> u64 {
    let d = attest_core::sha256(path.as_bytes());
    u64::from_le_bytes(d[..8].try_into().unwrap())
}

fn dir_stat(path: &str) -> Filestat {
    Filestat {
        device_id: 1,
        inode: inode(path),
        filetype: FileType::Directory,
        nlink: 1,
        size: 0,
        atim: None,
        mtim: None,
        ctim: None,
    }
}

/// Resolve `rel` (from the guest, relative to `base`) to a bundle path.
fn join(base: &str, rel: &str) -> Result<String, Error> {
    let mut parts: Vec<&str> = if base.is_empty() {
        vec![]
    } else {
        base.split('/').collect()
    };
    for c in rel.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop().ok_or_else(Error::perm)?;
            }
            c => parts.push(c),
        }
    }
    Ok(parts.join("/"))
}

struct RoDir {
    source: Source,
    prefix: String,
    /// For the repository: record which files were opened.
    opened: Option<Arc<Mutex<BTreeMap<String, [u8; 32]>>>>,
    /// Host-side work this invocation may still cause (see charge).
    budget: Arc<std::sync::atomic::AtomicU64>,
}

impl RoDir {
    /// Charge host-side work: an open is 1, a directory listing 1 per 64
    /// entries. The 512 MiB memory limit covers only the guest's own
    /// memory, so this bounds the host allocations a script can cause.
    fn charge(&self, units: u64) -> Result<(), Error> {
        use std::sync::atomic::Ordering::Relaxed;
        self.budget
            .fetch_update(Relaxed, Relaxed, |b| b.checked_sub(units))
            .map(|_| ())
            .map_err(|_| Error::perm().context("the script opened too many files or listed too many directories"))
    }
}

#[async_trait::async_trait]
impl WasiDir for RoDir {
    fn as_any(&self) -> &dyn Any {
        self
    }

    async fn open_file(
        &self,
        _follow: bool,
        path: &str,
        oflags: OFlags,
        _read: bool,
        write: bool,
        _fd: FdFlags,
    ) -> Result<OpenResult, Error> {
        if write || oflags.intersects(OFlags::CREATE | OFlags::TRUNCATE | OFlags::EXCLUSIVE) {
            return Err(Error::perm());
        }
        self.charge(1)?;
        let full = join(&self.prefix, path)?;
        if self.source.is_dir(&full) {
            return Ok(OpenResult::Dir(Box::new(RoDir {
                source: self.source.clone(),
                prefix: full,
                opened: self.opened.clone(),
                budget: self.budget.clone(),
            })));
        }
        let (_, digest) = self.source.file(&full).ok_or_else(Error::not_found)?;
        if oflags.contains(OFlags::DIRECTORY) {
            return Err(Error::not_dir());
        }
        let data = self.source.read(&full).await?;
        if let Some(o) = &self.opened {
            o.lock().unwrap().insert(full.clone(), digest);
        }
        Ok(OpenResult::File(Box::new(RepoFile {
            path: full,
            data,
            pos: Mutex::new(0),
        })))
    }

    async fn readdir(
        &self,
        cursor: ReaddirCursor,
    ) -> Result<Box<dyn Iterator<Item = Result<ReaddirEntity, Error>> + Send>, Error> {
        let prefix = if self.prefix.is_empty() {
            String::new()
        } else {
            format!("{}/", self.prefix)
        };
        let mut names: Vec<(String, FileType)> = vec![
            (".".into(), FileType::Directory),
            ("..".into(), FileType::Directory),
        ];
        names.extend(self.source.children(&prefix));
        self.charge(1 + names.len() as u64 / 64)?;
        let start = u64::from(cursor) as usize;
        let base = self.prefix.clone();
        let items: Vec<Result<ReaddirEntity, Error>> = names
            .into_iter()
            .enumerate()
            .skip(start)
            .map(|(i, (name, filetype))| {
                Ok(ReaddirEntity {
                    next: ReaddirCursor::from(i as u64 + 1),
                    inode: inode(&format!("{base}/{name}")),
                    name,
                    filetype,
                })
            })
            .collect();
        Ok(Box::new(items.into_iter()))
    }

    async fn get_filestat(&self) -> Result<Filestat, Error> {
        Ok(dir_stat(&self.prefix))
    }

    async fn get_path_filestat(&self, path: &str, _follow: bool) -> Result<Filestat, Error> {
        let full = join(&self.prefix, path)?;
        if self.source.is_dir(&full) {
            return Ok(dir_stat(&full));
        }
        let (size, _) = self.source.file(&full).ok_or_else(Error::not_found)?;
        Ok(Filestat {
            device_id: 1,
            inode: inode(&full),
            filetype: FileType::RegularFile,
            nlink: 1,
            size,
            atim: None,
            mtim: None,
            ctim: None,
        })
    }
}

struct RepoFile {
    path: String,
    data: Arc<Vec<u8>>,
    pos: Mutex<u64>,
}

#[async_trait::async_trait]
impl WasiFile for RepoFile {
    fn as_any(&self) -> &dyn Any {
        self
    }
    async fn get_filetype(&self) -> Result<FileType, Error> {
        Ok(FileType::RegularFile)
    }
    async fn get_filestat(&self) -> Result<Filestat, Error> {
        Ok(Filestat {
            device_id: 1,
            inode: inode(&self.path),
            filetype: FileType::RegularFile,
            nlink: 1,
            size: self.data.len() as u64,
            atim: None,
            mtim: None,
            ctim: None,
        })
    }
    async fn read_vectored<'a>(&self, bufs: &mut [IoSliceMut<'a>]) -> Result<u64, Error> {
        let mut pos = self.pos.lock().unwrap();
        let n = read_at(&self.data, *pos, bufs);
        *pos += n;
        Ok(n)
    }
    async fn read_vectored_at<'a>(
        &self,
        bufs: &mut [IoSliceMut<'a>],
        offset: u64,
    ) -> Result<u64, Error> {
        Ok(read_at(&self.data, offset, bufs))
    }
    async fn seek(&self, to: SeekFrom) -> Result<u64, Error> {
        let mut pos = self.pos.lock().unwrap();
        let len = self.data.len() as i64;
        let new = match to {
            SeekFrom::Start(n) => i64::try_from(n).ok(),
            SeekFrom::End(d) => len.checked_add(d),
            SeekFrom::Current(d) => i64::try_from(*pos).ok().and_then(|p| p.checked_add(d)),
        };
        let Some(new) = new.filter(|n| *n >= 0) else {
            return Err(Error::invalid_argument());
        };
        *pos = new as u64;
        Ok(*pos)
    }
    fn num_ready_bytes(&self) -> Result<u64, Error> {
        Ok((self.data.len() as u64).saturating_sub(*self.pos.lock().unwrap()))
    }
}

fn read_at(data: &[u8], offset: u64, bufs: &mut [IoSliceMut<'_>]) -> u64 {
    let mut off = offset as usize;
    let mut total = 0;
    for b in bufs.iter_mut() {
        if off >= data.len() {
            break;
        }
        let n = b.len().min(data.len() - off);
        b[..n].copy_from_slice(&data[off..off + n]);
        off += n;
        total += n;
    }
    total as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blobs::{BlobClient, Cache};

    /// Needs the CPython WASI build (tests/e2e.py fetches it to
    /// target/python-wasi); skipped without it.
    #[test]
    fn python_time_limit_covers_sleep_and_busy_loops() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/python-wasi");
        if !dir.join("python.wasm").exists() {
            eprintln!("skipping: no {}", dir.display());
            return;
        }
        let sb = Sandbox::load(&dir).unwrap();
        // One thread: if the guest didn't yield, nothing else could run.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut tar = tar::Builder::new(Vec::new());
            let mut h = tar::Header::new_gnu();
            h.set_size(1);
            h.set_cksum();
            tar.append_data(&mut h, "a.txt", &b"x"[..]).unwrap();
            let t = tar.into_inner().unwrap();
            let handle = tokio::runtime::Handle::current();
            let bundle = Arc::new(
                tokio::task::spawn_blocking(move || {
                    Bundle::ingest(
                        &t[..],
                        "s",
                        BlobClient::memory(),
                        Arc::new(Cache::new(1 << 20)),
                        handle,
                        1 << 20,
                    )
                })
                .await
                .unwrap()
                .unwrap(),
            );
            for code in ["import time\ntime.sleep(1000)", "while True:\n    pass"] {
                let ticks = Arc::new(std::sync::atomic::AtomicU64::new(0));
                let t2 = ticks.clone();
                let counter = tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        t2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                });
                let started = std::time::Instant::now();
                let out = sb
                    .run_python_within(
                        bundle.clone(),
                        code,
                        Default::default(),
                        Duration::from_secs(3),
                    )
                    .await;
                counter.abort();
                let took = started.elapsed();
                assert!(out.timed_out, "{code}: {:?}", out.error);
                assert!(took < Duration::from_secs(8), "{code}: took {took:?}");
                assert!(
                    ticks.load(std::sync::atomic::Ordering::Relaxed) > 10,
                    "{code}: the runtime was starved"
                );
            }
        });
    }
}
