"""A private server: only the operator key starts sessions.

    python3 tests/private_e2e.py     (builds and starts everything itself)
"""
import json
import os
import subprocess
import sys
import tempfile
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from handoff_e2e import BIN, ROOT, check, ok, wait_up  # noqa: E402

TUNNEL, BLOBS, PORT = 46301, 46305, 48301
KEY = "operator-key-0123456789abcdef"


def create(key=None):
    h = {"content-type": "application/json"}
    if key is not None:
        h["x-operator-key"] = key
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}/api/sessions", data=b"{}", method="POST", headers=h)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def main():
    subprocess.run(["cargo", "build", "--offline", "-q", "--manifest-path", os.path.join(ROOT, "Cargo.toml")], check=True)
    work = tempfile.mkdtemp(prefix="attest-private-")
    cfg = os.path.join(work, "enclave.json")
    with open(cfg, "w") as f:
        json.dump({"operator": "Example Operator", "operator_key": KEY}, f)
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
        info = ok(PORT, "GET", "/api/info")
        check(info["open"] is False and info["operator"] == "Example Operator", "the server says it's private, and who runs it")
        st, v = create()
        check(st == 403 and "private" in v.get("error", ""), "no key: no session")
        st, v = create("wrong-key-wrong-key-wrong")
        check(st == 403, "a wrong key: no session")
        st, v = create(KEY)
        check(st == 200 and v["auditor_link"], "the operator key starts a session")
        ok(PORT, "POST", f"/api/sessions/{v['session_id']}/question", v["auditor_token"], {"text": "Anyone with the link takes part?"})
        check(True, "the auditor takes part with just their link")
        print("ALL PRIVATE CHECKS PASSED")
    except SystemExit:
        print(open(log).read()[-2000:])
        raise
    finally:
        for p in procs:
            p.kill()


if __name__ == "__main__":
    main()
