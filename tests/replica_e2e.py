"""Standby test: a second dev enclave takes the lineage's keys, checks the
primary is alive, and takes over when the primary dies.

    python3 tests/replica_e2e.py     (builds and starts everything itself)

Enclave A serves a session; B starts as A's standby and serves no
sessions. B copies no session data: once A has been silent long enough,
the operator promotes B, which finds every session in the shared store
(including one made after B started) and serves the release made just
before A died, a verifying certificate, and the uploaded code for a new
run. Then C stands by for B.
"""
import hashlib
import hmac
import json
import os
import signal
import struct
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from handoff_e2e import BIN, ROOT, call, check, ok, trace, verify, wait_run, wait_up  # noqa: E402

MOCK, TUNNEL, BLOBS = 49999, 45101, 45105
PORTS = {"A": 48101, "B": 48102, "C": 48103}
TOKEN = "test-handoff-token-0123456789"


def mac(token, *parts):
    h = hashlib.sha256(b"".join(struct.pack("<Q", len(p)) + p for p in parts)).digest()
    return hmac.new(token.encode(), h, hashlib.sha256).hexdigest()


def promote(port, token=TOKEN):
    return call(port, "POST", "/api/internal/replica/promote", body={"mac": mac(token, b"attest-replica-promote/1")})


def main():
    subprocess.run(["cargo", "build", "--offline", "-q", "--manifest-path", os.path.join(ROOT, "Cargo.toml")], check=True)
    work = tempfile.mkdtemp(prefix="attest-replica-")
    procs = [
        subprocess.Popen([sys.executable, "-I", os.path.join(ROOT, "tests", "mock_llm.py"), str(MOCK)]),
        subprocess.Popen([os.path.join(BIN, "attest-host"), "--dev", "--no-forward", "--dev-tunnel", f"127.0.0.1:{TUNNEL}",
                          "--dev-blobs", f"127.0.0.1:{BLOBS}", "--blob-dir", os.path.join(work, "blobs")],
                         stderr=open(os.path.join(work, "host.log"), "w")),
    ]
    enclaves = {}

    def enclave(name, peer=None, standby=False):
        cfg = os.path.join(work, f"{name}.json")
        with open(cfg, "w") as f:
            c = {"handoff_token": TOKEN}
            if peer:
                c["peer"] = f"127.0.0.1:{PORTS[peer]}"
                c["standby"] = standby
            json.dump(c, f)
        log = os.path.join(work, f"{name}.log")
        p = subprocess.Popen([os.path.join(BIN, "attest-enclave"), "--dev", "--dev-listen", f"127.0.0.1:{PORTS[name]}",
                              "--dev-tunnel", f"127.0.0.1:{TUNNEL}", "--dev-blobs", f"127.0.0.1:{BLOBS}",
                              "--dev-config", cfg, "--python-dir", os.path.join(work, "no-python")],
                             stderr=open(log, "w"))
        procs.append(p)
        enclaves[name] = p
        wait_up(PORTS[name], log)
        return PORTS[name]

    try:
        run(work, enclave, enclaves)
        print("ALL REPLICA CHECKS PASSED")
    except SystemExit:
        for n in enclaves:
            print(f"--- {n}.log (tail)\n" + open(os.path.join(work, f"{n}.log")).read()[-1500:])
        raise
    finally:
        for p in procs:
            p.kill()


def run(work, enclave, enclaves):
    repo = os.path.join(work, "repo")
    os.makedirs(os.path.join(repo, "trainer"))
    with open(os.path.join(repo, "trainer", "train.py"), "w") as f:
        f.write('def build_loss_mask(tokens, include_cot):\n    return [t.kind != "cot" or include_cot for t in tokens]\n')
    g = lambda *a: subprocess.run(["git", "-C", repo, *a], check=True, capture_output=True)
    g("init", "-q"); g("config", "user.email", "t@t"); g("config", "user.name", "t"); g("add", "."); g("commit", "-qm", "init")

    print("enclave A, and B standing by for it")
    A = enclave("A")
    info_a = ok(A, "GET", "/api/info")
    s = ok(A, "POST", "/api/sessions", body={})
    sid, ae, ao = s["session_id"], s["auditee_token"], s["auditor_token"]
    B = enclave("B", peer="A", standby=True)
    info_b = ok(B, "GET", "/api/info")
    check(info_b["lineage"]["id"] == info_a["lineage"]["id"], "B holds A's lineage")
    check(ok(B, "GET", "/api/health")["standby"] is True, "B reports itself as a standby")
    st, v = call(B, "GET", f"/api/sessions/{sid}", ae)
    check(st == 503 and v.get("standby"), "B serves no sessions while standing by")
    check(call(B, "POST", "/api/sessions", body={})[0] == 503, "B creates no sessions while standing by")
    check(call(A, "GET", f"/api/sessions/{sid}", ae)[0] == 200, "A keeps serving after B took its copy")

    print("work on A")
    ok(A, "POST", f"/api/sessions/{sid}/question", ao, {"text": "Does trainer/train.py compute loss on chain-of-thought tokens?"})
    ok(A, "POST", f"/api/sessions/{sid}/question/decision", ae, {"version": 1, "accept": True})
    up = subprocess.run([os.path.join(BIN, "attest"), "upload", f"http://127.0.0.1:{A}/s/{sid}#{ae}", repo, "--org", "Example Lab", "--allow-dev"],
                        capture_output=True, text=True)
    check(up.returncode == 0, "code uploaded to A")
    ok(A, "POST", f"/api/sessions/{sid}/models", ae, {"provider": "mock", "model": "gpt-mock", "api_key": "test-key", "mock_endpoint": f"127.0.0.1:{MOCK}"})
    v = wait_run(A, sid, ae, lambda rs: rs[-1]["status"] == "awaiting_release", "run 1")
    r1 = v["runs"][-1]["id"]
    trace1 = trace(A, sid, ae, r1)

    st, v = promote(B)
    check(st == 403 and "unreachable" in v.get("error", ""), "B refuses promotion while A answers")
    late = ok(A, "POST", "/api/sessions", body={})
    ok(A, "POST", f"/api/sessions/{late['session_id']}/question", late["auditor_token"], {"text": "Made after B started?"})

    t = time.time()
    ok(A, "POST", f"/api/sessions/{sid}/runs/{r1}/release", ae, {"release": True})
    check(time.time() - t < 2, "the release is answered without waiting on B")
    # Killed once the release is written (every couple of seconds).
    time.sleep(3)
    enclaves["A"].send_signal(signal.SIGKILL)
    enclaves["A"].wait()

    print("A dies; the operator promotes B")
    st, v = promote(B, token="wrong-token-wrong-token")
    check(st == 403 and "token" in v.get("error", ""), "promotion needs the operator's token")
    time.sleep(22)
    st, v = promote(B)
    check(st == 200 and v["restored"] == 2, f"B promoted after A went silent, with both sessions ({v})")
    lv = ok(B, "GET", f"/api/sessions/{late['session_id']}", late["auditee_token"])
    check(lv["questions"][-1]["text"] == "Made after B started?", "B has the session made after it started")
    check(ok(B, "GET", "/api/health")["standby"] is False, "B now serves")
    va = ok(B, "GET", f"/api/sessions/{sid}", ao)
    run1 = next(r for r in va["runs"] if r["id"] == r1)
    check(run1["status"] == "released", "the release made just before A died is on B")
    cert = ok(B, "GET", f"/api/sessions/{sid}/runs/{r1}/certificate", ao)
    good, _ = verify(cert, work, "cert.json")
    check(good, "the certificate verifies")
    check(trace(B, sid, ae, r1) == trace1, "B serves the same trace")
    ok(B, "POST", f"/api/sessions/{sid}/question", ao, {"text": "Does trainer/train.py ever drop chain-of-thought tokens from the loss?"})
    ok(B, "POST", f"/api/sessions/{sid}/question/decision", ae, {"version": 2, "accept": True})
    v = wait_run(B, sid, ae, lambda rs: len(rs) == 2 and rs[-1]["status"] == "awaiting_release", "run 2 on B")
    check(v["runs"][-1]["outcome"] == {"kind": "completed"}, "B reads the uploaded code for a new run")
    r2 = v["runs"][-1]["id"]
    st, v = promote(B)
    check(st == 403, "promoting twice is refused")

    print("C stands by for B")
    C = enclave("C", peer="B", standby=True)
    check(ok(C, "GET", "/api/health")["standby"] is True, "C stands by")
    check(call(C, "GET", f"/api/sessions/{sid}", ae)[0] == 503, "C serves no sessions")
    ok(B, "POST", f"/api/sessions/{sid}/runs/{r2}/release", ae, {"release": False})
    time.sleep(3)
    enclaves["B"].send_signal(signal.SIGKILL)
    enclaves["B"].wait()
    time.sleep(22)
    st, v = promote(C)
    check(st == 200, "C promoted after B died")
    runs = {r["id"]: r for r in ok(C, "GET", f"/api/sessions/{sid}", ao)["runs"]}
    check(runs[r1]["status"] == "released" and runs[r2]["status"] == "declined",
          "C has both the release from A's time and the decline from B's")

if __name__ == "__main__":
    main()
