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
    let mut ok = |name: &str, r: Result<String, String>| out.push(match r {
        Ok(s) => format!("{name}=ok{}", if s.is_empty() { String::new() } else { format!("({s})") }),
        Err(e) => format!("{name}=FAIL({e})"),
    });
    unsafe {
        let mut u: libc::utsname = std::mem::zeroed();
        libc::uname(&mut u);
        let rel = std::ffi::CStr::from_ptr(u.release.as_ptr()).to_string_lossy().into_owned();
        ok("kernel", Ok(rel));
        let flags = libc::CLONE_NEWNS | libc::CLONE_NEWNET | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS | libc::CLONE_NEWPID;
        ok("unshare", if libc::unshare(flags) == 0 { Ok(String::new()) } else { Err(errno()) });
        let root = CString::new("/").unwrap();
        ok("mount_private", if libc::mount(std::ptr::null(), root.as_ptr(), std::ptr::null(), libc::MS_REC | libc::MS_PRIVATE, std::ptr::null()) == 0 { Ok(String::new()) } else { Err(errno()) });
        let dir = "/tmp/jail-probe";
        let _ = std::fs::create_dir_all(dir);
        let (d, t, o) = (CString::new(dir).unwrap(), CString::new("tmpfs").unwrap(), CString::new("size=20m,mode=1777").unwrap());
        let tmpfs = libc::mount(t.as_ptr(), d.as_ptr(), t.as_ptr(), 0, o.as_ptr() as *const _) == 0;
        ok("tmpfs", if tmpfs { Ok(String::new()) } else { Err(errno()) });
        if tmpfs {
            let big = vec![0u8; 21 << 20];
            let r = std::fs::write(format!("{dir}/big"), &big);
            ok("tmpfs_cap", match r {
                Err(e) if e.raw_os_error() == Some(libc::ENOSPC) => Ok("20 MiB enforced".into()),
                Err(e) => Err(e.to_string()),
                Ok(()) => Err("wrote 21 MiB into a 20 MiB tmpfs".into()),
            });
        }
        // Loopback in the new network namespace.
        let s = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        let mut ifr: libc::ifreq = std::mem::zeroed();
        for (i, b) in b"lo".iter().enumerate() {
            ifr.ifr_name[i] = *b as libc::c_char;
        }
        ifr.ifr_ifru.ifru_flags = (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
        ok("loopback_up", if s >= 0 && libc::ioctl(s, libc::SIOCSIFFLAGS as _, &ifr) == 0 { Ok(String::new()) } else { Err(errno()) });
        libc::close(s);
        ok("no_new_privs", if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 { Ok(String::new()) } else { Err(errno()) });
        // seccomp: refuse vsock sockets.
        let filter = seccompiler::SeccompFilter::new(
            vec![(
                libc::SYS_socket,
                vec![seccompiler::SeccompRule::new(vec![seccompiler::SeccompCondition::new(
                    0,
                    seccompiler::SeccompCmpArgLen::Dword,
                    seccompiler::SeccompCmpOp::Eq,
                    libc::AF_VSOCK as u64,
                )
                .unwrap()])
                .unwrap()],
            )]
            .into_iter()
            .collect(),
            seccompiler::SeccompAction::Allow,
            seccompiler::SeccompAction::Errno(libc::EPERM as u32),
            seccompiler::TargetArch::aarch64,
        );
        let installed = filter
            .and_then(|f| -> Result<seccompiler::BpfProgram, seccompiler::BackendError> { f.try_into() })
            .map_err(|e| e.to_string())
            .and_then(|p| seccompiler::apply_filter(&p).map_err(|e| e.to_string()));
        ok("seccomp", installed.clone().map(|_| String::new()));
        if installed.is_ok() {
            let v = libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0);
            ok("vsock_blocked", if v < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) { Ok(String::new()) } else { Err(format!("socket returned {v}")) });
        }
        let dropped = libc::setgid(65534) == 0 && libc::setuid(65534) == 0;
        ok("drop_privileges", if dropped { Ok(String::new()) } else { Err(errno()) });
        let nsm = std::fs::File::open("/dev/nsm");
        ok("nsm_unreadable_unprivileged", match nsm {
            Err(e) if e.raw_os_error() == Some(libc::EACCES) || e.raw_os_error() == Some(libc::EPERM) => Ok(String::new()),
            Err(e) => Ok(format!("open failed: {e}")),
            Ok(_) => Err("unprivileged process can open /dev/nsm".into()),
        });
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
        let _ = std::fs::set_permissions("/dev/nsm", std::os::unix::fs::PermissionsExt::from_mode(0o600));
    }
    std::thread::spawn(|| {
        let exe = std::env::current_exe().unwrap_or_else(|_| "/attest-enclave".into());
        match std::process::Command::new(exe).arg("--jail-probe").output() {
            Ok(o) => crate::log(&format!("jail probe: {}{}", String::from_utf8_lossy(&o.stdout).trim(), if o.status.success() { "" } else { " (exit failure)" })),
            Err(e) => crate::log(&format!("jail probe could not start: {e}")),
        }
    });
}
