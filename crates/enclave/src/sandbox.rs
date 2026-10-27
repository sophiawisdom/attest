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
use std::path::{Path, PathBuf};
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

pub struct Sandbox {
    engine: Engine,
    module: Module,
    stdlib: PathBuf,
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
        let wasm = std::fs::read(dir.join("python.wasm")).with_context(|| format!("reading {}/python.wasm", dir.display()))?;
        let module = Module::new(&engine, &wasm).map_err(|e| anyhow!("compiling python.wasm: {e}"))?;
        // One ticker for the engine; per-call deadlines count ticks.
        let ticker = engine.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(TICK);
            ticker.increment_epoch();
        });
        Ok(Self { engine, module, stdlib: dir.join("lib") })
    }

    pub async fn run_python(&self, bundle: Arc<Bundle>, code: &str, opened: Arc<Mutex<BTreeMap<String, [u8; 32]>>>) -> Output {
        let stdout = Capped::default();
        let stderr = Capped::default();
        let result = self.run_inner(bundle, code, opened, stdout.clone(), stderr.clone()).await;
        let (exit_code, timed_out, error) = match result {
            Ok(code) => (Some(code), false, None),
            Err(e) => {
                let msg = format!("{e:#}");
                let timed_out = msg.contains("interrupt") || msg.contains("epoch");
                (None, timed_out, if timed_out { None } else { Some(msg) })
            }
        };
        Output { stdout: stdout.text(), stderr: stderr.text(), exit_code, timed_out, error }
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
        b.args(&["python".into(), "-I".into(), "-B".into(), "-c".into(), code.into()]).map_err(|e| anyhow!("{e}"))?;
        b.env("PYTHONIOENCODING", "utf-8").map_err(|e| anyhow!("{e}"))?;
        b.env("PYTHONDONTWRITEBYTECODE", "1").map_err(|e| anyhow!("{e}"))?;
        b.stdout(Box::new(wasi_common::pipe::WritePipe::new(stdout)));
        b.stderr(Box::new(wasi_common::pipe::WritePipe::new(stderr)));
        let stdlib = cap_std::fs::Dir::open_ambient_dir(&self.stdlib, cap_std::ambient_authority()).context("opening stdlib")?;
        b.preopened_dir(stdlib, "/usr/local/lib").map_err(|e| anyhow!("{e}"))?;
        let wasi = b.build();
        wasi.push_preopened_dir(Box::new(RepoDir { bundle, prefix: String::new(), opened }), "/repo").map_err(|e| anyhow!("{e}"))?;

        let limits = StoreLimitsBuilder::new().memory_size(MEMORY_LIMIT).instances(4).tables(64).memories(4).build();
        let mut store = Store::new(&self.engine, GuestState { wasi, limits });
        store.limiter(|s| &mut s.limits);
        store.set_epoch_deadline((TIME_LIMIT.as_millis() / TICK.as_millis()) as u64);
        store.epoch_deadline_trap();
        let mut linker: Linker<GuestState> = Linker::new(&self.engine);
        wasi_common::tokio::add_to_linker(&mut linker, |s| &mut s.wasi).map_err(|e| anyhow!("{e}"))?;
        linker.module_async(&mut store, "", &self.module).await.map_err(|e| anyhow!("{e}"))?;
        let start = linker.get_default(&mut store, "").map_err(|e| anyhow!("{e}"))?.typed::<(), ()>(&store).map_err(|e| anyhow!("{e}"))?;
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
            s.push_str(&format!("\n[... {} more bytes of output not shown]", g.1 - g.0.len()));
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
    Filestat { device_id: 1, inode: inode(path), filetype: FileType::Directory, nlink: 1, size: 0, atim: None, mtim: None, ctim: None }
}

/// Resolve `rel` (from the guest, relative to `base`) to a bundle path.
fn join(base: &str, rel: &str) -> Result<String, Error> {
    let mut parts: Vec<&str> = if base.is_empty() { vec![] } else { base.split('/').collect() };
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

struct RepoDir {
    bundle: Arc<Bundle>,
    prefix: String,
    opened: Arc<Mutex<BTreeMap<String, [u8; 32]>>>,
}

#[async_trait::async_trait]
impl WasiDir for RepoDir {
    fn as_any(&self) -> &dyn Any {
        self
    }

    async fn open_file(&self, _follow: bool, path: &str, oflags: OFlags, _read: bool, write: bool, _fd: FdFlags) -> Result<OpenResult, Error> {
        if write || oflags.intersects(OFlags::CREATE | OFlags::TRUNCATE | OFlags::EXCLUSIVE) {
            return Err(Error::perm());
        }
        let full = join(&self.prefix, path)?;
        if self.bundle.dirs.contains(&full) {
            return Ok(OpenResult::Dir(Box::new(RepoDir { bundle: self.bundle.clone(), prefix: full, opened: self.opened.clone() })));
        }
        let entry = self.bundle.files.get(&full).ok_or_else(Error::not_found)?;
        if oflags.contains(OFlags::DIRECTORY) {
            return Err(Error::not_dir());
        }
        let data = self.bundle.read(&full).await.map_err(|_| Error::io())?;
        self.opened.lock().unwrap().insert(full.clone(), entry.digest);
        Ok(OpenResult::File(Box::new(RepoFile { path: full, data, pos: Mutex::new(0) })))
    }

    async fn readdir(&self, cursor: ReaddirCursor) -> Result<Box<dyn Iterator<Item = Result<ReaddirEntity, Error>> + Send>, Error> {
        let prefix = if self.prefix.is_empty() { String::new() } else { format!("{}/", self.prefix) };
        let mut names: Vec<(String, FileType)> = vec![(".".into(), FileType::Directory), ("..".into(), FileType::Directory)];
        for d in self.bundle.dirs.range(prefix.clone()..) {
            if !d.starts_with(&prefix) {
                break;
            }
            let rest = &d[prefix.len()..];
            if !rest.is_empty() && !rest.contains('/') {
                names.push((rest.to_string(), FileType::Directory));
            }
        }
        for (p, _) in self.bundle.files.range(prefix.clone()..) {
            if !p.starts_with(&prefix) {
                break;
            }
            let rest = &p[prefix.len()..];
            if !rest.contains('/') {
                names.push((rest.to_string(), FileType::RegularFile));
            }
        }
        let start = u64::from(cursor) as usize;
        let base = self.prefix.clone();
        let items: Vec<Result<ReaddirEntity, Error>> = names
            .into_iter()
            .enumerate()
            .skip(start)
            .map(|(i, (name, filetype))| Ok(ReaddirEntity { next: ReaddirCursor::from(i as u64 + 1), inode: inode(&format!("{base}/{name}")), name, filetype }))
            .collect();
        Ok(Box::new(items.into_iter()))
    }

    async fn get_filestat(&self) -> Result<Filestat, Error> {
        Ok(dir_stat(&self.prefix))
    }

    async fn get_path_filestat(&self, path: &str, _follow: bool) -> Result<Filestat, Error> {
        let full = join(&self.prefix, path)?;
        if self.bundle.dirs.contains(&full) {
            return Ok(dir_stat(&full));
        }
        let e = self.bundle.files.get(&full).ok_or_else(Error::not_found)?;
        Ok(Filestat { device_id: 1, inode: inode(&full), filetype: FileType::RegularFile, nlink: 1, size: e.size, atim: None, mtim: None, ctim: None })
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
        Ok(Filestat { device_id: 1, inode: inode(&self.path), filetype: FileType::RegularFile, nlink: 1, size: self.data.len() as u64, atim: None, mtim: None, ctim: None })
    }
    async fn read_vectored<'a>(&self, bufs: &mut [IoSliceMut<'a>]) -> Result<u64, Error> {
        let mut pos = self.pos.lock().unwrap();
        let n = read_at(&self.data, *pos, bufs);
        *pos += n;
        Ok(n)
    }
    async fn read_vectored_at<'a>(&self, bufs: &mut [IoSliceMut<'a>], offset: u64) -> Result<u64, Error> {
        Ok(read_at(&self.data, offset, bufs))
    }
    async fn seek(&self, to: SeekFrom) -> Result<u64, Error> {
        let mut pos = self.pos.lock().unwrap();
        let len = self.data.len() as i64;
        let new = match to {
            SeekFrom::Start(n) => n as i64,
            SeekFrom::End(d) => len + d,
            SeekFrom::Current(d) => *pos as i64 + d,
        };
        if new < 0 {
            return Err(Error::invalid_argument());
        }
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
