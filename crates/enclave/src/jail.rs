#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]
//! Native jail for real agent harnesses (Codex, pi, ...), Linux only.
//!
//! For now: a probe of which kernel features the enclave's (fixed,
//! nitro-cli supplied) kernel offers. It runs in a child process so that
//! changing namespaces cannot disturb the server.

#[cfg(target_os = "linux")]
pub fn probe() -> String {
    use std::ffi::CString;
    let mut out: Vec<String> = Vec::new();
    let errno = || std::io::Error::last_os_error().to_string();
    let mut ok = |name: &str, r: Result<String, String>| {
        out.push(match r {
            Ok(s) => format!(
                "{name}=ok{}",
                if s.is_empty() {
                    String::new()
                } else {
                    format!("({s})")
                }
            ),
            Err(e) => format!("{name}=FAIL({e})"),
        })
    };
    unsafe {
        let mut u: libc::utsname = std::mem::zeroed();
        libc::uname(&mut u);
        let rel = std::ffi::CStr::from_ptr(u.release.as_ptr())
            .to_string_lossy()
            .into_owned();
        ok("kernel", Ok(rel));
        let flags = libc::CLONE_NEWNS
            | libc::CLONE_NEWNET
            | libc::CLONE_NEWIPC
            | libc::CLONE_NEWUTS
            | libc::CLONE_NEWPID;
        ok(
            "unshare",
            if libc::unshare(flags) == 0 {
                Ok(String::new())
            } else {
                Err(errno())
            },
        );
        let root = CString::new("/").unwrap();
        ok(
            "mount_private",
            if libc::mount(
                std::ptr::null(),
                root.as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            ) == 0
            {
                Ok(String::new())
            } else {
                Err(errno())
            },
        );
        let dir = "/tmp/jail-probe";
        let _ = std::fs::create_dir_all(dir);
        let (d, t, o) = (
            CString::new(dir).unwrap(),
            CString::new("tmpfs").unwrap(),
            CString::new("size=20m,mode=1777").unwrap(),
        );
        let tmpfs = libc::mount(
            t.as_ptr(),
            d.as_ptr(),
            t.as_ptr(),
            0,
            o.as_ptr() as *const _,
        ) == 0;
        ok(
            "tmpfs",
            if tmpfs {
                Ok(String::new())
            } else {
                Err(errno())
            },
        );
        if tmpfs {
            let big = vec![0u8; 21 << 20];
            let r = std::fs::write(format!("{dir}/big"), &big);
            ok(
                "tmpfs_cap",
                match r {
                    Err(e) if e.raw_os_error() == Some(libc::ENOSPC) => {
                        Ok("20 MiB enforced".into())
                    }
                    Err(e) => Err(e.to_string()),
                    Ok(()) => Err("wrote 21 MiB into a 20 MiB tmpfs".into()),
                },
            );
        }
        // Loopback in the new network namespace.
        let s = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        let mut ifr: libc::ifreq = std::mem::zeroed();
        for (i, b) in b"lo".iter().enumerate() {
            ifr.ifr_name[i] = *b as libc::c_char;
        }
        ifr.ifr_ifru.ifru_flags = (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
        ok(
            "loopback_up",
            if s >= 0 && libc::ioctl(s, libc::SIOCSIFFLAGS as _, &ifr) == 0 {
                Ok(String::new())
            } else {
                Err(errno())
            },
        );
        libc::close(s);
        ok(
            "no_new_privs",
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 {
                Ok(String::new())
            } else {
                Err(errno())
            },
        );
        // seccomp: refuse vsock sockets.
        let filter = seccompiler::SeccompFilter::new(
            vec![(
                libc::SYS_socket,
                vec![
                    seccompiler::SeccompRule::new(vec![seccompiler::SeccompCondition::new(
                        0,
                        seccompiler::SeccompCmpArgLen::Dword,
                        seccompiler::SeccompCmpOp::Eq,
                        libc::AF_VSOCK as u64,
                    )
                    .unwrap()])
                    .unwrap(),
                ],
            )]
            .into_iter()
            .collect(),
            seccompiler::SeccompAction::Allow,
            seccompiler::SeccompAction::Errno(libc::EPERM as u32),
            seccompiler::TargetArch::aarch64,
        );
        let installed = filter
            .and_then(
                |f| -> Result<seccompiler::BpfProgram, seccompiler::BackendError> { f.try_into() },
            )
            .map_err(|e| e.to_string())
            .and_then(|p| seccompiler::apply_filter(&p).map_err(|e| e.to_string()));
        ok("seccomp", installed.clone().map(|_| String::new()));
        if installed.is_ok() {
            let v = libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0);
            ok(
                "vsock_blocked",
                if v < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) {
                    Ok(String::new())
                } else {
                    Err(format!("socket returned {v}"))
                },
            );
        }
        let dropped = libc::setgid(65534) == 0 && libc::setuid(65534) == 0;
        ok(
            "drop_privileges",
            if dropped {
                Ok(String::new())
            } else {
                Err(errno())
            },
        );
        let nsm = std::fs::File::open("/dev/nsm");
        ok(
            "nsm_unreadable_unprivileged",
            match nsm {
                Err(e)
                    if e.raw_os_error() == Some(libc::EACCES)
                        || e.raw_os_error() == Some(libc::EPERM) =>
                {
                    Ok(String::new())
                }
                Err(e) => Ok(format!("open failed: {e}")),
                Ok(_) => Err("unprivileged process can open /dev/nsm".into()),
            },
        );
    }
    out.join(" ")
}

#[cfg(not(target_os = "linux"))]
pub fn probe() -> String {
    "not linux".into()
}

/// Run the probe in a child process and log the result.
pub fn spawn_probe() {
    #[cfg(target_os = "linux")]
    {
        // Only root may open the attestation device; jailed processes run as nobody.
        let _ = std::fs::set_permissions(
            "/dev/nsm",
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        );
    }
    std::thread::spawn(|| {
        let exe = std::env::current_exe().unwrap_or_else(|_| "/attest-enclave".into());
        match std::process::Command::new(exe).arg("--jail-probe").output() {
            Ok(o) => crate::log(&format!(
                "jail probe: {}{}",
                String::from_utf8_lossy(&o.stdout).trim(),
                if o.status.success() {
                    ""
                } else {
                    " (exit failure)"
                }
            )),
            Err(e) => crate::log(&format!("jail probe could not start: {e}")),
        }
    });
}

// ------------------------------------------------------------------ running a jailed program

/// What `--jail-exec` should run. Passed as JSON on the command line.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct Spec {
    /// Prepared repository (a tmpfs the server filled), bound at /repo.
    pub repo: String,
    /// Read-only image content bound at /bin and /usr (busybox, harness binaries).
    pub image_root: String,
    /// Where to assemble the jail's root.
    pub scratch: String,
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: String,
    /// Size of /work and /tmp, in MiB each.
    pub work_mib: u32,
    /// Files under /work to hand back after the program exits.
    pub collect: Vec<String>,
    /// The run's model proxy (a Unix socket outside the jail), and the
    /// loopback port inside the jail's own network namespace bridged to it.
    pub proxy_socket: String,
    pub proxy_port: u16,
}

pub const RESULT_MARKER: &str = "ATTEST-JAIL-RESULT ";

/// Entry point of `attest-enclave --jail-exec SPEC_JSON` (a fresh, single-threaded process).
#[cfg(target_os = "linux")]
pub fn exec_main(spec_json: &str) -> ! {
    let code = match exec_inner(spec_json) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("jail: {e:#}");
            125
        }
    };
    std::process::exit(code)
}

#[cfg(target_os = "linux")]
fn cstr(s: &str) -> std::ffi::CString {
    std::ffi::CString::new(s).expect("no NUL in path")
}

#[cfg(target_os = "linux")]
fn check(r: libc::c_int, what: &str) -> anyhow::Result<()> {
    if r == 0 {
        Ok(())
    } else {
        anyhow::bail!("{what}: {}", std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
unsafe fn mount(
    src: &str,
    dst: &str,
    fstype: &str,
    flags: libc::c_ulong,
    data: &str,
) -> anyhow::Result<()> {
    let (s, d, t, o) = (cstr(src), cstr(dst), cstr(fstype), cstr(data));
    check(
        libc::mount(
            s.as_ptr(),
            d.as_ptr(),
            if fstype.is_empty() {
                std::ptr::null()
            } else {
                t.as_ptr()
            },
            flags,
            if data.is_empty() {
                std::ptr::null()
            } else {
                o.as_ptr() as *const _
            },
        ),
        &format!("mount {dst}"),
    )
}

#[cfg(target_os = "linux")]
unsafe fn bind(src: &str, dst: &str, read_only: bool) -> anyhow::Result<()> {
    mount(src, dst, "", libc::MS_BIND | libc::MS_REC, "")?;
    if read_only {
        mount(
            "",
            dst,
            "",
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
            "",
        )?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn exec_inner(spec_json: &str) -> anyhow::Result<i32> {
    use anyhow::Context;
    let spec: Spec = serde_json::from_str(spec_json).context("jail spec")?;
    let root = format!("{}/root", spec.scratch);
    unsafe {
        // A new, empty network namespace: the only thing the jail can reach
        // is its own loopback, where one port is bridged to the model proxy.
        check(
            libc::unshare(
                libc::CLONE_NEWNS
                    | libc::CLONE_NEWPID
                    | libc::CLONE_NEWIPC
                    | libc::CLONE_NEWUTS
                    | libc::CLONE_NEWNET,
            ),
            "unshare",
        )?;
        if !set_loopback_up() {
            anyhow::bail!(
                "bringing up the jail's loopback: {}",
                std::io::Error::last_os_error()
            );
        }
        let bridge = std::net::TcpListener::bind(("127.0.0.1", spec.proxy_port))
            .context("jail proxy port")?;
        mount("", "/", "", libc::MS_REC | libc::MS_PRIVATE, "")?;
        std::fs::create_dir_all(&root)?;
        mount(
            "tmpfs",
            &root,
            "tmpfs",
            libc::MS_NOSUID | libc::MS_NODEV,
            "size=16m,mode=0755",
        )?;
        for d in [
            "bin", "usr", "repo", "work", "tmp", "dev", "proc", "etc", ".old",
        ] {
            std::fs::create_dir_all(format!("{root}/{d}"))?;
        }
        bind(
            &format!("{}/bin", spec.image_root),
            &format!("{root}/bin"),
            true,
        )?;
        bind(
            &format!("{}/usr", spec.image_root),
            &format!("{root}/usr"),
            true,
        )?;
        // The repository: root-owned, mode 0444/0555, so the agent can read
        // but not change it, and reads still update access times.
        bind(&spec.repo, &format!("{root}/repo"), false)?;
        let opts = format!("size={}m,mode=1777", spec.work_mib);
        mount(
            "tmpfs",
            &format!("{root}/work"),
            "tmpfs",
            libc::MS_NOSUID | libc::MS_NODEV,
            &opts,
        )?;
        mount(
            "tmpfs",
            &format!("{root}/tmp"),
            "tmpfs",
            libc::MS_NOSUID | libc::MS_NODEV,
            &opts,
        )?;
        mount(
            "tmpfs",
            &format!("{root}/dev"),
            "tmpfs",
            libc::MS_NOSUID,
            "size=64k,mode=0755",
        )?;
        for dev in ["null", "zero", "urandom", "random"] {
            let p = format!("{root}/dev/{dev}");
            std::fs::write(&p, b"")?;
            bind(&format!("/dev/{dev}"), &p, false)?;
        }
        std::fs::write(
            format!("{root}/etc/passwd"),
            "root:x:0:0::/:/bin/sh\nnobody:x:65534:65534::/work:/bin/sh\n",
        )?;
        std::fs::write(format!("{root}/etc/group"), "root:x:0:\nnogroup:x:65534:\n")?;
        std::fs::write(format!("{root}/etc/hosts"), "127.0.0.1 localhost\n")?;
        let host = cstr("attest-jail");
        libc::sethostname(host.as_ptr(), 11);

        let pid = libc::fork();
        if pid < 0 {
            anyhow::bail!("fork: {}", std::io::Error::last_os_error());
        }
        if pid == 0 {
            // PID 1 of the new namespace: finish the jail and exec.
            let r = child(&spec, &root);
            eprintln!("jail: {:#}", r.unwrap_err());
            libc::_exit(126);
        }
        // Bridge loopback connections from the jail to the model proxy.
        let sock = spec.proxy_socket.clone();
        std::thread::spawn(move || {
            for conn in bridge.incoming().flatten() {
                let sock = sock.clone();
                std::thread::spawn(move || {
                    let Ok(up) = std::os::unix::net::UnixStream::connect(&sock) else {
                        return;
                    };
                    let (mut a, mut b) = (conn.try_clone().unwrap(), up.try_clone().unwrap());
                    let t = std::thread::spawn(move || {
                        let _ = std::io::copy(&mut a, &mut b);
                        let _ = b.shutdown(std::net::Shutdown::Write);
                    });
                    let (mut c, mut d) = (up, conn);
                    let _ = std::io::copy(&mut c, &mut d);
                    let _ = d.shutdown(std::net::Shutdown::Write);
                    let _ = t.join();
                });
            }
        });
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        let code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            128 + libc::WTERMSIG(status)
        };
        // Hand back requested files from /work (still mounted in this
        // namespace). The agent controls /work, so: no root, no symlinks, no
        // FIFOs or devices, bounded size.
        libc::setgroups(0, std::ptr::null());
        if libc::setgid(65534) != 0 || libc::setuid(65534) != 0 {
            anyhow::bail!("dropping privileges before collecting results");
        }
        let mut files = serde_json::Map::new();
        for f in &spec.collect {
            if f.contains('/') {
                continue;
            }
            if let Some(b) = read_regular_nofollow(&format!("{root}/work/{f}"), 256 << 10) {
                files.insert(
                    f.clone(),
                    serde_json::Value::String(String::from_utf8_lossy(&b).into_owned()),
                );
            }
        }
        println!(
            "{RESULT_MARKER}{}",
            serde_json::json!({"exit": code, "files": files})
        );
        Ok(code)
    }
}

/// Read a regular file without following a symlink at its final component.
#[cfg(target_os = "linux")]
fn read_regular_nofollow(path: &str, max: usize) -> Option<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::io::FromRawFd;
    let p = cstr(path);
    let fd = unsafe {
        libc::open(
            p.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return None;
    }
    let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
    let meta = f.metadata().ok()?;
    if !meta.file_type().is_file() {
        return None;
    }
    let mut buf = Vec::new();
    (&mut f).take(max as u64).read_to_end(&mut buf).ok()?;
    Some(buf)
}

#[cfg(target_os = "linux")]
unsafe fn child(spec: &Spec, root: &str) -> anyhow::Result<std::convert::Infallible> {
    let parent = libc::getppid();
    mount(
        "proc",
        &format!("{root}/proc"),
        "proc",
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        "",
    )?;
    let (new, old) = (cstr(root), cstr(&format!("{root}/.old")));
    check(
        libc::syscall(libc::SYS_pivot_root, new.as_ptr(), old.as_ptr()) as libc::c_int,
        "pivot_root",
    )?;
    std::env::set_current_dir("/")?;
    let old_root = cstr("/.old");
    check(
        libc::umount2(old_root.as_ptr(), libc::MNT_DETACH),
        "umount old root",
    )?;
    let _ = std::fs::remove_dir("/.old");
    // Remount the jail root read-only now that it's assembled.
    mount(
        "",
        "/",
        "",
        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
        "",
    )?;
    std::env::set_current_dir(&spec.cwd)?;
    let lim = |r, v: u64| {
        let l = libc::rlimit {
            rlim_cur: v,
            rlim_max: v,
        };
        libc::setrlimit(r, &l);
    };
    lim(libc::RLIMIT_NPROC, 512);
    lim(libc::RLIMIT_NOFILE, 4096);
    lim(libc::RLIMIT_CORE, 0);
    check(
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
        "no_new_privs",
    )?;
    install_seccomp()?;
    check(libc::setgroups(0, std::ptr::null()), "setgroups")?;
    check(libc::setgid(65534), "setgid")?;
    check(libc::setuid(65534), "setuid")?;
    // Die with our parent: if the server kills it, the whole namespace goes.
    // (Set after the uid change, which clears it.)
    libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
    if libc::getppid() != parent {
        libc::_exit(137);
    }
    let argv: Vec<std::ffi::CString> = spec.argv.iter().map(|a| cstr(a)).collect();
    let env: Vec<std::ffi::CString> = spec
        .env
        .iter()
        .map(|(k, v)| cstr(&format!("{k}={v}")))
        .collect();
    let mut argv_p: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    argv_p.push(std::ptr::null());
    let mut env_p: Vec<*const libc::c_char> = env.iter().map(|a| a.as_ptr()).collect();
    env_p.push(std::ptr::null());
    libc::execve(argv_p[0], argv_p.as_ptr(), env_p.as_ptr());
    anyhow::bail!("exec {}: {}", spec.argv[0], std::io::Error::last_os_error())
}

/// Allow everything except: sockets other than Unix and IP (so no vsock to
/// the parent, netlink or raw packets), debugging other processes, and
/// changing mounts, namespaces or the kernel. (IP sockets can only reach the
/// jail's own loopback: its network namespace has nothing else.)
#[cfg(target_os = "linux")]
fn install_seccomp() -> anyhow::Result<()> {
    use seccompiler::{
        SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule,
    };
    let mut rules: std::collections::BTreeMap<i64, Vec<SeccompRule>> =
        std::collections::BTreeMap::new();
    let not = |f: i32| {
        SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Ne, f as u64).unwrap()
    };
    // Conditions in one rule are ANDed: refuse any family that is none of these.
    rules.insert(
        libc::SYS_socket,
        vec![SeccompRule::new(vec![
            not(libc::AF_UNIX),
            not(libc::AF_INET),
            not(libc::AF_INET6),
        ])
        .unwrap()],
    );
    rules.insert(
        libc::SYS_socketpair,
        vec![SeccompRule::new(vec![not(libc::AF_UNIX)]).unwrap()],
    );
    for sys in [
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_kexec_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_reboot,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_userfaultfd,
        libc::SYS_open_by_handle_at,
        libc::SYS_name_to_handle_at,
    ] {
        rules.insert(sys, vec![]);
    }
    let f = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        seccompiler::TargetArch::aarch64,
    )
    .map_err(|e| anyhow::anyhow!("seccomp: {e}"))?;
    let prog: seccompiler::BpfProgram = f
        .try_into()
        .map_err(|e: seccompiler::BackendError| anyhow::anyhow!("seccomp: {e}"))?;
    seccompiler::apply_filter(&prog).map_err(|e| anyhow::anyhow!("seccomp: {e}"))
}

#[cfg(not(target_os = "linux"))]
pub fn exec_main(_spec_json: &str) -> ! {
    eprintln!("jail: linux only");
    std::process::exit(125)
}

/// Fill a fresh size-limited tmpfs at `dir` with the bundle's files:
/// root-owned, read-only to everyone else. Linux only.
#[cfg(target_os = "linux")]
pub async fn materialize(bundle: &crate::bundle::Bundle, dir: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir)?;
    let size_mib = (bundle.info.total_bytes >> 20) + bundle.info.file_count / 64 + 64;
    unsafe {
        mount(
            "tmpfs",
            dir,
            "tmpfs",
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_STRICTATIME,
            &format!("size={size_mib}m,mode=0555"),
        )?
    };
    for d in bundle.dirs.iter().filter(|d| !d.is_empty()) {
        let p = format!("{dir}/{d}");
        std::fs::create_dir_all(&p)?;
    }
    for (path, _) in bundle.files.iter() {
        let data = bundle.read(path).await?;
        let p = format!("{dir}/{path}");
        tokio::fs::write(&p, &*data).await?;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o444))?;
    }
    for d in bundle.dirs.iter() {
        std::fs::set_permissions(format!("{dir}/{d}"), std::fs::Permissions::from_mode(0o555))?;
    }
    Ok(())
}

/// Files under `dir` whose access time is at or after `since` (strictatime
/// mount): what the jailed agent read.
#[cfg(target_os = "linux")]
pub fn accessed_since(dir: &str, since: std::time::SystemTime) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![std::path::PathBuf::from(dir)];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let Ok(m) = e.metadata() else { continue };
            if m.is_dir() {
                stack.push(e.path());
            } else if m.accessed().map(|a| a >= since).unwrap_or(false) {
                if let Ok(rel) = e.path().strip_prefix(dir) {
                    out.push(rel.to_string_lossy().into_owned());
                }
            }
        }
    }
    out.sort();
    out
}

#[cfg(target_os = "linux")]
pub fn unmount(dir: &str) {
    let d = cstr(dir);
    unsafe {
        libc::umount2(d.as_ptr(), libc::MNT_DETACH);
    }
    let _ = std::fs::remove_dir(dir);
}

/// Bring up loopback in the calling process's network namespace.
#[cfg(target_os = "linux")]
fn set_loopback_up() -> bool {
    unsafe {
        let s = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        let mut ifr: libc::ifreq = std::mem::zeroed();
        for (i, b) in b"lo".iter().enumerate() {
            ifr.ifr_name[i] = *b as libc::c_char;
        }
        ifr.ifr_ifru.ifru_flags = (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
        let ok = s >= 0 && libc::ioctl(s, libc::SIOCSIFFLAGS as _, &ifr) == 0;
        libc::close(s);
        ok
    }
}
