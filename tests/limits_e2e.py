"""Session limit and live limit changes.

    python3 tests/limits_e2e.py     (builds and starts everything itself)

An enclave booted with max_sessions 3 refuses a fourth session once the
three are in use, takes more after the operator raises the limit with
deploy/limits.py, and keeps every session when the limit is lowered.
"""
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from handoff_e2e import BIN, ROOT, call, check, ok, wait_up  # noqa: E402

TUNNEL, BLOBS, PORT = 46101, 46105, 48201
TOKEN = "test-handoff-token-0123456789"


def limits(token=TOKEN, **kw):
    args = [sys.executable, os.path.join(ROOT, "deploy", "limits.py"), f"http://127.0.0.1:{PORT}"]
    for k, v in kw.items():
        args += [f"--{k.replace('_', '-')}", str(v)]
    r = subprocess.run(args, capture_output=True, text=True, env={**os.environ, "HANDOFF_TOKEN": token})
    return r.returncode, (json.loads(r.stdout) if r.returncode == 0 else r.stderr)


def main():
    subprocess.run(["cargo", "build", "--offline", "-q", "--manifest-path", os.path.join(ROOT, "Cargo.toml")], check=True)
    work = tempfile.mkdtemp(prefix="attest-limits-")
    cfg = os.path.join(work, "enclave.json")
    with open(cfg, "w") as f:
        json.dump({"handoff_token": TOKEN, "max_sessions": 3}, f)
    log = os.path.join(work, "enclave.log")
    procs = [
        subprocess.Popen([os.path.join(BIN, "attest-host"), "--dev", "--no-forward", "--dev-tunnel", f"127.0.0.1:{TUNNEL}",
                          "--dev-blobs", f"127.0.0.1:{BLOBS}", "--blob-dir", os.path.join(work, "blobs")],
                         stderr=open(os.path.join(work, "host.log"), "w")),
        subprocess.Popen([os.path.join(BIN, "attest-enclave"), "--dev", "--dev-listen", f"127.0.0.1:{PORT}",
                          "--dev-tunnel", f"127.0.0.1:{TUNNEL}", "--dev-blobs", f"127.0.0.1:{BLOBS}",
                          "--dev-config", cfg, "--python-dir", os.path.join(work, "no-python")],
                         stderr=open(log, "w")),
    ]
    try:
        wait_up(PORT, log)

        def session():
            s = ok(PORT, "POST", "/api/sessions", body={})
            ok(PORT, "POST", f"/api/sessions/{s['session_id']}/question", s["auditor_token"], {"text": "Is the loss masked?"})
            return s

        made = [session() for _ in range(3)]
        st, v = call(PORT, "POST", "/api/sessions", body={})
        check(st != 200 and "session limit" in v.get("error", ""), "a fourth session is refused at the configured limit of 3")

        st, v = limits()
        check(st == 0 and v["max_sessions"] == 3 and v["sessions"] == 3, f"the operator sees the limits ({v})")
        check(v["session_memory_used_mib"] < v["session_memory_mib"], "session memory is under its budget")
        st, v = limits(token="wrong-token-wrong-token", max_sessions=50)
        check(st != 0 and "token" in v, "changing limits needs the handoff token")

        st, v = limits(max_sessions=4)
        check(st == 0 and v["max_sessions"] == 4, "the operator raises the limit live")
        made.append(session())
        check(call(PORT, "POST", "/api/sessions", body={})[0] != 200, "the new limit holds")

        st, v = limits(max_sessions=2)
        check(st == 0 and v["sessions"] == 4, "lowering the limit keeps every session")
        for s in made:
            ok(PORT, "GET", f"/api/sessions/{s['session_id']}", s["auditee_token"])
        check(True, "all four sessions still serve")
        st, v = limits(max_sessions=10**9, session_memory_mib=10**9)
        check(st == 0 and v["max_sessions"] == 10_000 and v["session_memory_mib"] == v["session_memory_max_mib"],
              f"out-of-range limits are clamped ({v})")
        print("ALL LIMITS CHECKS PASSED")
    except SystemExit:
        print(open(log).read()[-2000:])
        raise
    finally:
        for p in procs:
            p.kill()


if __name__ == "__main__":
    main()
