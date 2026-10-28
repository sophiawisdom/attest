//! Per-run resource limits for jailed agents: a cgroup with memory, process
//! count and CPU caps, and a reliable way to kill everything in it.
//!
//! The Nitro enclave kernel (4.14) has cgroup v1 controllers; a dev machine
//! usually has the unified v2 hierarchy. Both are handled. The jailed
//! process can't leave its cgroup (it can't write to cgroupfs, which isn't
//! mounted in the jail), so killing every member is a dependable end to a
//! run, unlike the parent-death signal, which the jailed process can clear.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Limits for one run.
pub struct Limits {
    pub memory_bytes: u64,
    pub pids: u32,
    /// CPU time per wall-clock second, in CPUs (1.0 = one full CPU).
    pub cpus: f64,
}

#[derive(Debug)]
enum Layout {
    /// cgroup v1: one directory per controller.
    V1 { memory: PathBuf, pids: PathBuf, cpu: PathBuf },
    /// cgroup v2: one parent directory for attest's runs.
    V2 { parent: PathBuf },
}

static LAYOUT: OnceLock<std::result::Result<Layout, String>> = OnceLock::new();

/// Find or mount the controllers. Called once at startup; the result says
/// whether jailed runs can have limits.
pub fn init() -> Result<()> {
    match LAYOUT.get_or_init(|| detect().map_err(|e| format!("{e:#}"))) {
        Ok(_) => Ok(()),
        Err(e) => bail!("{e}"),
    }
}

fn layout() -> Result<&'static Layout> {
    match LAYOUT.get_or_init(|| detect().map_err(|e| format!("{e:#}"))) {
        Ok(l) => Ok(l),
        Err(e) => bail!("cgroups unavailable: {e}"),
    }
}

/// The machine's (enclave's) memory, from /proc/meminfo.
pub fn mem_total() -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|m| {
            m.lines()
                .find(|l| l.starts_with("MemTotal:"))
                .and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
        })
        .map(|kib| kib * 1024)
        .unwrap_or(8 << 30)
}

/// Memory all jailed agents together may use: 40% of the enclave's. The
/// rest is for the service, the repositories it holds for runs (see
/// sessions::code_memory) and the Python sandbox.
pub fn jails_memory() -> u64 {
    mem_total() / 10 * 4
}

/// CPU all jailed agents together may use: all but half a CPU, so the
/// service always keeps some.
fn jails_cpus() -> f64 {
    let n = std::thread::available_parallelism().map_or(2, |n| n.get()) as f64;
    (n - 0.5).max(0.5)
}

const PERIOD_US: u64 = 100_000;

fn detect() -> Result<Layout> {
    let base = Path::new("/sys/fs/cgroup");
    let quota = (jails_cpus() * PERIOD_US as f64) as u64;
    let layout = if base.join("cgroup.controllers").exists() {
        // Unified hierarchy. Enable the controllers for our subtree.
        let parent = base.join("attest");
        std::fs::create_dir_all(&parent).context("creating /sys/fs/cgroup/attest")?;
        let _ = std::fs::write(base.join("cgroup.subtree_control"), "+memory +pids +cpu");
        std::fs::write(parent.join("cgroup.subtree_control"), "+memory +pids +cpu")
            .context("enabling memory, pids and cpu controllers")?;
        // Aggregate caps over every run's cgroup.
        std::fs::write(parent.join("memory.max"), jails_memory().to_string())
            .context("capping the jails' memory")?;
        std::fs::write(parent.join("cpu.max"), format!("{quota} {PERIOD_US}"))
            .context("capping the jails' CPU")?;
        Layout::V2 { parent }
    } else {
        let mut dirs = Vec::new();
        for (name, opts) in [("memory", "memory"), ("pids", "pids"), ("cpu", "cpu,cpuacct")] {
            let dir = find_v1(name).map(Ok).unwrap_or_else(|| mount_v1(name, opts))?;
            let ours = dir.join("attest");
            std::fs::create_dir_all(&ours)
                .with_context(|| format!("creating {}", ours.display()))?;
            dirs.push(ours);
        }
        let cpu = dirs.pop().unwrap();
        let pids = dirs.pop().unwrap();
        let memory = dirs.pop().unwrap();
        // Aggregate caps over every run's cgroup. In v1, memory limits only
        // cover children with use_hierarchy, which must be set while the
        // parent has none (it may already be on, and then can't be written).
        let _ = std::fs::write(memory.join("memory.use_hierarchy"), "1");
        std::fs::write(memory.join("memory.limit_in_bytes"), jails_memory().to_string())
            .context("capping the jails' memory")?;
        std::fs::write(cpu.join("cpu.cfs_period_us"), PERIOD_US.to_string())
            .context("capping the jails' CPU")?;
        std::fs::write(cpu.join("cpu.cfs_quota_us"), quota.to_string())
            .context("capping the jails' CPU")?;
        Layout::V1 { memory, pids, cpu }
    };
    reap_leftovers(&layout);
    Ok(layout)
}

/// Kill and remove run cgroups left from an earlier service process, and
/// any this process failed to remove before.
fn reap_leftovers(layout: &Layout) {
    let parents: Vec<&PathBuf> = match layout {
        Layout::V2 { parent } => vec![parent],
        Layout::V1 { memory, pids, cpu } => vec![memory, pids, cpu],
    };
    let mut dirs: Vec<PathBuf> = parents
        .iter()
        .filter_map(|p| std::fs::read_dir(p).ok())
        .flatten()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("run-"))
        .map(|e| e.path())
        .collect();
    dirs.extend(std::mem::take(&mut *LEFTOVERS.lock().unwrap_or_else(|e| e.into_inner())));
    dirs.sort();
    dirs.dedup();
    if dirs.is_empty() {
        return;
    }
    // Dropping removes them, or puts them back on the list.
    drop(RunCgroup { dirs });
}

/// Run cgroups whose processes couldn't all be killed yet; retried before
/// every new run.
static LEFTOVERS: std::sync::Mutex<Vec<PathBuf>> = std::sync::Mutex::new(Vec::new());

/// Where a v1 controller is mounted, from /proc/self/mountinfo.
fn find_v1(controller: &str) -> Option<PathBuf> {
    let info = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    for line in info.lines() {
        let (pre, post) = line.split_once(" - ")?;
        let mut post = post.split_whitespace();
        if post.next() != Some("cgroup") {
            continue;
        }
        let opts = post.nth(1).unwrap_or("");
        if opts.split(',').any(|o| o == controller) {
            return pre.split_whitespace().nth(4).map(PathBuf::from);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn mount_v1(name: &str, opts: &str) -> Result<PathBuf> {
    let dir = PathBuf::from(format!("/run/attest-cgroup/{name}"));
    std::fs::create_dir_all(&dir)?;
    let c = |s: &str| std::ffi::CString::new(s).unwrap();
    let (src, dst, ty, o) = (c("cgroup"), c(dir.to_str().unwrap()), c("cgroup"), c(opts));
    let r = unsafe { libc::mount(src.as_ptr(), dst.as_ptr(), ty.as_ptr(), 0, o.as_ptr() as *const _) };
    if r != 0 {
        bail!("mounting the {name} cgroup controller: {}", std::io::Error::last_os_error());
    }
    Ok(dir)
}

#[cfg(not(target_os = "linux"))]
fn mount_v1(name: &str, _opts: &str) -> Result<PathBuf> {
    bail!("no {name} cgroup controller (linux only)")
}

/// One run's cgroup. Dropping it kills anything left in it and removes it.
pub struct RunCgroup {
    dirs: Vec<PathBuf>,
}

impl RunCgroup {
    pub fn create(run_id: &str, l: &Limits) -> Result<Self> {
        anyhow::ensure!(
            !run_id.is_empty() && run_id.chars().all(|c| c.is_ascii_alphanumeric()),
            "bad run id"
        );
        let name = format!("run-{run_id}");
        let period = PERIOD_US;
        let quota = ((l.cpus * period as f64) as u64).max(1000);
        let w = |dir: &Path, file: &str, v: String| {
            std::fs::write(dir.join(file), &v)
                .with_context(|| format!("setting {file} = {v} in {}", dir.display()))
        };
        let layout = layout()?;
        // Retry anything an earlier run couldn't clean up.
        if !LEFTOVERS.lock().unwrap_or_else(|e| e.into_inner()).is_empty() {
            reap_leftovers(layout);
        }
        // The guard owns each directory before it's created, so a failure
        // halfway removes what was made.
        let cg = match layout {
            Layout::V2 { parent } => {
                let d = parent.join(&name);
                let cg = RunCgroup { dirs: vec![d.clone()] };
                std::fs::create_dir_all(&d)?;
                w(&d, "memory.max", l.memory_bytes.to_string())?;
                let _ = w(&d, "memory.swap.max", "0".into());
                w(&d, "pids.max", l.pids.to_string())?;
                w(&d, "cpu.max", format!("{quota} {period}"))?;
                cg
            }
            Layout::V1 { memory, pids, cpu } => {
                let (m, p, c) = (memory.join(&name), pids.join(&name), cpu.join(&name));
                let cg = RunCgroup { dirs: vec![m.clone(), p.clone(), c.clone()] };
                for d in [&m, &p, &c] {
                    std::fs::create_dir_all(d)?;
                }
                w(&m, "memory.limit_in_bytes", l.memory_bytes.to_string())?;
                // Present only with swap accounting; the enclave has no swap anyway.
                let _ = w(&m, "memory.memsw.limit_in_bytes", l.memory_bytes.to_string());
                w(&p, "pids.max", l.pids.to_string())?;
                w(&c, "cpu.cfs_period_us", period.to_string())?;
                w(&c, "cpu.cfs_quota_us", quota.to_string())?;
                cg
            }
        };
        Ok(cg)
    }

    /// Files the jailed process writes "0" to, to join this cgroup.
    pub fn procs_files(&self) -> Vec<String> {
        self.dirs
            .iter()
            .map(|d| d.join("cgroup.procs").to_string_lossy().into_owned())
            .collect()
    }

    fn members(&self) -> Vec<i32> {
        let mut v: Vec<i32> = self
            .dirs
            .iter()
            .filter_map(|d| std::fs::read_to_string(d.join("cgroup.procs")).ok())
            .flat_map(|s| s.lines().filter_map(|l| l.trim().parse().ok()).collect::<Vec<_>>())
            .collect();
        v.sort();
        v.dedup();
        v
    }

    /// SIGKILL every process in the cgroup until it is empty. Returns
    /// whether it emptied.
    pub fn kill_all(&self) -> bool {
        for _ in 0..200 {
            let m = self.members();
            if m.is_empty() {
                return true;
            }
            for pid in m {
                #[cfg(target_os = "linux")]
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
                #[cfg(not(target_os = "linux"))]
                let _ = pid;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        false
    }
}

impl Drop for RunCgroup {
    fn drop(&mut self) {
        let emptied = self.kill_all();
        let mut left = Vec::new();
        for d in self.dirs.drain(..) {
            if !d.exists() {
                continue;
            }
            if !emptied || std::fs::remove_dir(&d).is_err() {
                left.push(d);
            }
        }
        if !left.is_empty() {
            crate::log("a jailed run's cgroup couldn't be emptied yet; retrying before the next run");
            LEFTOVERS.lock().unwrap_or_else(|e| e.into_inner()).extend(left);
        }
    }
}
