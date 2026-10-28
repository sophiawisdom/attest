"""Handoff test: sessions move from one dev enclave to another of the same
build, and on to a third, with everything still served and verifiable.

    python3 tests/handoff_e2e.py     (builds and starts everything itself)

Enclave A serves a session with code, a released run and a run awaiting
release. Enclave B starts with A as its peer and takes the sessions over:
B must serve the same session, run, trace and certificate, sign the
pending run's certificate itself (naming the boot it ran on), read the
uploaded code for a new run, and A must answer only that the sessions
moved. Then C takes over from B the same way.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "target", "debug")
MOCK, TUNNEL, BLOBS = 39999, 35101, 35105
PORTS = {"A": 38101, "B": 38102, "C": 38103}
TOKEN = "test-handoff-token-0123456789"


def call(port, method, path, token=None, body=None):
    headers = {"content-type": "application/json"}
    if token:
        headers["authorization"] = "Bearer " + token
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def ok(port, method, path, token=None, body=None):
    status, v = call(port, method, path, token, body)
    assert status == 200, f"{method} {path}: {status} {v}"
    return v


def check(cond, msg):
    if not cond:
        raise SystemExit("FAIL: " + msg)
    print("  ok:", msg)


def wait_up(port, log, timeout=120):
    end = time.time() + timeout
    while time.time() < end:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1)
            return
        except Exception:
            time.sleep(0.2)
    raise SystemExit(f"FAIL: enclave on {port} didn't come up:\n{open(log).read()[-2000:]}")


def wait_run(port, sid, token, pred, what, timeout=90):
    end = time.time() + timeout
    while time.time() < end:
        v = ok(port, "GET", f"/api/sessions/{sid}", token)
        if v["runs"] and pred(v["runs"]):
            return v
        time.sleep(0.3)
    raise SystemExit(f"FAIL: timed out waiting for {what}")


def trace(port, sid, token, run_id):
    out, nxt = [], 0
    while True:
        t = ok(port, "GET", f"/api/sessions/{sid}/runs/{run_id}/trace?after={nxt}", token)
        out += t["entries"]
        nxt = t["next"]
        if not t.get("more"):
            return out


def verify(cert, work, name):
    path = os.path.join(work, name)
    with open(path, "w") as f:
        json.dump(cert, f)
    r = subprocess.run([os.path.join(BIN, "attest"), "verify", path, "--allow-dev", "--json"], capture_output=True, text=True)
    return r.returncode == 0, (json.loads(r.stdout) if r.returncode == 0 else r.stderr)


def main():
    subprocess.run(["cargo", "build", "--offline", "-q", "--manifest-path", os.path.join(ROOT, "Cargo.toml")], check=True)
    work = tempfile.mkdtemp(prefix="attest-handoff-")
    procs = [
        subprocess.Popen([sys.executable, "-I", os.path.join(ROOT, "tests", "mock_llm.py"), str(MOCK)]),
        subprocess.Popen([os.path.join(BIN, "attest-host"), "--dev", "--no-forward", "--dev-tunnel", f"127.0.0.1:{TUNNEL}",
                          "--dev-blobs", f"127.0.0.1:{BLOBS}", "--blob-dir", os.path.join(work, "blobs")],
                         stderr=open(os.path.join(work, "host.log"), "w")),
    ]

    def enclave(name, peer=None):
        cfg = os.path.join(work, f"{name}.json")
        with open(cfg, "w") as f:
            c = {"handoff_token": TOKEN}
            if peer:
                c["peer"] = f"127.0.0.1:{PORTS[peer]}"
            json.dump(c, f)
        log = os.path.join(work, f"{name}.log")
        procs.append(subprocess.Popen([os.path.join(BIN, "attest-enclave"), "--dev", "--dev-listen", f"127.0.0.1:{PORTS[name]}",
                                       "--dev-tunnel", f"127.0.0.1:{TUNNEL}", "--dev-blobs", f"127.0.0.1:{BLOBS}",
                                       "--dev-config", cfg, "--python-dir", os.path.join(work, "no-python")],
                                      stderr=open(log, "w")))
        wait_up(PORTS[name], log)
        return PORTS[name]

    try:
        run(work, enclave)
        print("ALL HANDOFF CHECKS PASSED")
    finally:
        for p in procs:
            p.kill()


def run(work, enclave):
    repo = os.path.join(work, "repo")
    os.makedirs(os.path.join(repo, "trainer"))
    with open(os.path.join(repo, "trainer", "train.py"), "w") as f:
        f.write('def build_loss_mask(tokens, include_cot):\n    return [t.kind != "cot" or include_cot for t in tokens]\n\n'
                'def main():\n    include_cot = True\n    mask = build_loss_mask(load(), include_cot)\n')
    g = lambda *a: subprocess.run(["git", "-C", repo, *a], check=True, capture_output=True)
    g("init", "-q"); g("config", "user.email", "t@t"); g("config", "user.name", "t"); g("add", "."); g("commit", "-qm", "init")

    print("enclave A: a session with a released run and a run awaiting release")
    A = enclave("A")
    info_a = ok(A, "GET", "/api/info")
    check(info_a["lineage"]["generation"] == 0 and info_a["lineage"]["restored_from_boot"] is None, "A starts a lineage")
    s = ok(A, "POST", "/api/sessions", body={})
    sid, ae, ao = s["session_id"], s["auditee_token"], s["auditor_token"]
    ok(A, "POST", f"/api/sessions/{sid}/question", ao, {"text": "Does trainer/train.py compute loss on chain-of-thought tokens?"})
    ok(A, "POST", f"/api/sessions/{sid}/question/decision", ae, {"version": 1, "accept": True})
    up = subprocess.run([os.path.join(BIN, "attest"), "upload", f"http://127.0.0.1:{A}/s/{sid}#{ae}", repo, "--org", "Example Lab", "--allow-dev"],
                        capture_output=True, text=True)
    check(up.returncode == 0, "code uploaded to A")
    ok(A, "POST", f"/api/sessions/{sid}/models", ae, {"provider": "mock", "model": "gpt-mock", "api_key": "test-key", "mock_endpoint": f"127.0.0.1:{MOCK}"})
    v = wait_run(A, sid, ae, lambda rs: rs[-1]["status"] == "awaiting_release", "run 1")
    r1 = v["runs"][-1]["id"]
    check(v["runs"][-1]["outcome"] == {"kind": "completed"} and v["runs"][-1]["verdict"]["answer"] == "yes", "run 1 completed on A")
    ok(A, "POST", f"/api/sessions/{sid}/runs/{r1}/release", ae, {"release": True})
    cert1 = ok(A, "GET", f"/api/sessions/{sid}/runs/{r1}/certificate", ao)
    trace1 = trace(A, sid, ae, r1)
    f = ok(A, "POST", f"/api/sessions/{sid}/runs/{r1}/followup", ao, {"text": "Check again, please."})
    v = wait_run(A, sid, ae, lambda rs: len(rs) == 2 and rs[-1]["status"] == "awaiting_release", "run 2")
    r2 = v["runs"][-1]["id"]
    before_auditee = ok(A, "GET", f"/api/sessions/{sid}", ae)
    before_auditor = ok(A, "GET", f"/api/sessions/{sid}", ao)

    print("handoffs need the operator's token")
    n = ok(A, "GET", "/api/internal/handoff/challenge")["nonce"]
    st, err = call(A, "POST", "/api/internal/handoff", body={"challenge": n, "public_key": "00" * 32, "nonce": "00" * 32, "token": "wrong-token-wrong-token"})
    check(st == 403 and "token" in err.get("error", ""), "a handoff request with the wrong token is refused")
    check(call(A, "GET", f"/api/sessions/{sid}", ae)[0] == 200, "A keeps serving after a refused handoff")

    print("enclave B takes over from A")
    B = enclave("B", peer="A")
    info_b = ok(B, "GET", "/api/info")
    check(info_b["lineage"]["id"] == info_a["lineage"]["id"] and info_b["lineage"]["generation"] == 1
          and info_b["lineage"]["restored_from_boot"] == info_a["boot_id"], "B continues A's lineage")
    check(info_b["signing_public_key"] == info_a["signing_public_key"] and info_b["boot_id"] != info_a["boot_id"],
          "B has the lineage's signing key and its own boot")
    st, err = call(A, "GET", f"/api/sessions/{sid}", ae)
    check(st == 503 and err.get("moved"), "A answers only that the sessions moved")
    st, _ = call(A, "POST", "/api/internal/handoff", body={})
    check(st != 200, "A hands over only once")

    after = ok(B, "GET", f"/api/sessions/{sid}", ae)
    check([r["id"] for r in after["runs"]] == [r1, r2], "B serves the session's runs")
    check(after["runs"][0]["status"] == "released" and after["runs"][0]["verdict"] == before_auditee["runs"][0]["verdict"],
          "the released run and its verdict are intact")
    check(after["questions"] == before_auditee["questions"] and after["affidavit"] == before_auditee["affidavit"]
          and after["code"] == before_auditee["code"], "question, affidavit and code metadata are intact")
    check(after["version"] > before_auditee["version"], "the auditee's version moved on, so clients refresh")
    after_o = ok(B, "GET", f"/api/sessions/{sid}", ao)
    check(after_o["runs"][1]["status"] == "running" and "verdict" not in after_o["runs"][1]
          and [e["seq"] for e in after_o["events"]] == [e["seq"] for e in before_auditor["events"]],
          "the auditor's view is unchanged: same events, run 2 still undecided")
    check(trace(B, sid, ae, r1) == trace1, "run 1's trace is intact")
    check(ok(B, "GET", f"/api/sessions/{sid}/runs/{r1}/certificate", ao) == cert1, "run 1's certificate is the same")
    good, out = verify(cert1, work, "cert1.json")
    check(good, f"run 1's certificate still verifies ({out if not good else ''})")

    ok(B, "POST", f"/api/sessions/{sid}/runs/{r2}/release", ae, {"release": True, "details": True})
    cert2 = ok(B, "GET", f"/api/sessions/{sid}/runs/{r2}/certificate", ao)
    good, out = verify(cert2, work, "cert2.json")
    check(good, f"run 2's certificate, signed by B, verifies ({out if not good else ''})")
    m2 = out["body"]["manifest"]
    check(m2["boot_id"] == info_b["boot_id"] and m2["ran_on_boot_id"] == info_a["boot_id"],
          "it names the boot it ran on (A) and the one that signed it (B)")

    print("a new run on B reads the code A stored")
    ok(B, "POST", f"/api/sessions/{sid}/runs/{r2}/followup", ao, {"text": "And once more."})
    v = wait_run(B, sid, ae, lambda rs: len(rs) == 3 and rs[-1]["status"] != "running", "run 3")
    r3 = v["runs"][-1]
    check(r3["outcome"] == {"kind": "completed"} and r3["verdict"]["answer"] == "yes", "run 3 completed on B with the stored code")

    print("a run still going on B when C takes over")
    s2 = ok(B, "POST", "/api/sessions", body={})
    sid2, ae2, ao2 = s2["session_id"], s2["auditee_token"], s2["auditor_token"]
    ok(B, "POST", f"/api/sessions/{sid2}/question", ao2, {"text": "SLOW: does trainer/train.py compute loss on chain-of-thought tokens?"})
    ok(B, "POST", f"/api/sessions/{sid2}/question/decision", ae2, {"version": 1, "accept": True})
    up = subprocess.run([os.path.join(BIN, "attest"), "upload", f"http://127.0.0.1:{B}/s/{sid2}#{ae2}", repo, "--org", "Example Lab", "--allow-dev"],
                        capture_output=True, text=True)
    check(up.returncode == 0, "code uploaded to B")
    ok(B, "POST", f"/api/sessions/{sid2}/models", ae2, {"provider": "mock", "model": "gpt-mock", "api_key": "test-key", "mock_endpoint": f"127.0.0.1:{MOCK}"})
    wait_run(B, sid2, ae2, lambda rs: rs[-1]["status"] == "running", "the slow run to start")

    print("enclave C takes over from B")
    trace3 = trace(B, sid, ae, r3["id"])
    C = enclave("C", peer="B")
    v2 = ok(C, "GET", f"/api/sessions/{sid2}", ae2)
    r = v2["runs"][-1]
    check(r["status"] == "awaiting_release" and r["outcome"]["kind"] == "error" and "interrupted" in r["outcome"]["message"],
          "the run that was going is recorded as interrupted, for the auditee to decide on")
    check(ok(C, "GET", f"/api/sessions/{sid2}", ao2)["runs"][-1]["status"] == "running", "the auditor still sees it as undecided")
    ok(C, "POST", f"/api/sessions/{sid2}/runs/{r['id']}/release", ae2, {"release": True})
    good, out = verify(ok(C, "GET", f"/api/sessions/{sid2}/runs/{r['id']}/certificate", ao2), work, "cert-interrupted.json")
    check(good and out["body"]["verdict"] is None and out["body"]["manifest"]["outcome"]["kind"] == "error",
          "its certificate verifies and says it failed")
    info_c = ok(C, "GET", "/api/info")
    check(info_c["lineage"]["generation"] == 2 and info_c["lineage"]["restored_from_boot"] == info_b["boot_id"], "C continues the lineage")
    v = ok(C, "GET", f"/api/sessions/{sid}", ae)
    check([r["id"] for r in v["runs"]] == [r1, r2, r3["id"]] and v["runs"][2]["verdict"] == r3["verdict"], "C serves all three runs")
    check(trace(C, sid, ae, r3["id"]) == trace3 and len(trace3) > 2, "run 3's trace moved too")
    check(call(B, "GET", f"/api/sessions/{sid}", ae)[0] == 503, "B now answers that the sessions moved")
    s2 = ok(C, "POST", "/api/sessions", body={})
    check(ok(C, "GET", f"/api/sessions/{s2['session_id']}", s2["auditee_token"])["role"] == "auditee", "C takes new sessions")


if __name__ == "__main__":
    main()
