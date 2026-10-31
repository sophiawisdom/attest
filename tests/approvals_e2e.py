"""Tool-call approval with the built-in agent, Claude Code, Codex and pi.

    python3 tests/approvals_e2e.py [builtin claude-code codex pi]

Needs Linux, root and the jail image at /opt/jailroot for the jailed
harnesses (mock models; no network). The test plays the auditee's agent: it
denies any call that touches secret.txt (and the built-in agent's read_file)
and approves the rest.
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from handoff_e2e import BIN, ROOT, call, check, ok, trace, wait_up  # noqa: E402

TUNNEL, BLOBS, PORT, AGENTS, LLM = 46801, 46805, 48801, 46891, 46899
WITHHELD = "withheld by the enclave"
decisions = []


def approver(sid, token, stop):
    """The auditee's agent: long-polls for pending calls and decides each."""
    while not stop.is_set():
        try:
            p = ok(PORT, "GET", f"/api/sessions/{sid}/tool-calls?wait=5", token)
        except (SystemExit, OSError) as e:
            print("   approver:", e)
            time.sleep(1)
            continue
        for c in p["pending"]:
            text = json.dumps(c["input"])
            approve = "secret" not in text and c["tool"] != "read_file"
            decisions.append((c["agent"], c["tool"], approve))
            ok(PORT, "POST", f"/api/sessions/{sid}/tool-calls/{c['id']}", token, {"approve": approve, "reason": "" if approve else "not that file"})


def main():
    agents = sys.argv[1:] or ["builtin", "claude-code", "codex", "pi"]
    subprocess.run(["cargo", "build", "--offline", "-q", "--manifest-path", os.path.join(ROOT, "Cargo.toml")], check=True)
    work = tempfile.mkdtemp(prefix="attest-approvals-")
    repo = os.path.join(work, "repo")
    os.makedirs(repo)
    open(os.path.join(repo, "secret.txt"), "w").write("TOPSECRET-4711\n")
    open(os.path.join(repo, "README.md"), "w").write("hello readme\n")
    open(os.path.join(repo, "train.py"), "w").write("include_cot = False\n")
    agent_log = os.path.join(work, "agents.jsonl")
    log = os.path.join(work, "enclave.log")
    procs = [
        subprocess.Popen([sys.executable, "-I", os.path.join(ROOT, "tests", "mock_llm.py"), str(LLM)]),
        subprocess.Popen([sys.executable, "-I", os.path.join(ROOT, "tests", "mock_agents.py"), str(AGENTS), agent_log]),
        subprocess.Popen([os.path.join(BIN, "attest-host"), "--dev", "--no-forward", "--dev-tunnel", f"127.0.0.1:{TUNNEL}",
                          "--dev-blobs", f"127.0.0.1:{BLOBS}", "--blob-dir", os.path.join(work, "blobs")],
                         stderr=open(os.path.join(work, "host.log"), "w")),
        subprocess.Popen([os.path.join(BIN, "attest-enclave"), "--dev", "--dev-listen", f"127.0.0.1:{PORT}",
                          "--dev-tunnel", f"127.0.0.1:{TUNNEL}", "--dev-blobs", f"127.0.0.1:{BLOBS}",
                          "--python-dir", os.path.join(work, "no-python")],
                         stderr=open(log, "w")),
    ]
    stop = threading.Event()
    try:
        wait_up(PORT, log)
        s = ok(PORT, "POST", "/api/sessions", body={})
        sid, ae, ao = s["session_id"], s["auditee_token"], s["auditor_token"]
        base = f"/api/sessions/{sid}"
        st, v = call(PORT, "POST", base + "/tool-approval", ao, {"enabled": True})
        check(st != 200, "only the auditee turns approval on")
        ok(PORT, "POST", base + "/tool-approval", ae, {"enabled": True})
        check(ok(PORT, "GET", base, ao)["tool_approval"] is True, "the auditor sees that the auditee approves tool calls")
        subprocess.run(["git", "init", "-q", repo], check=True)
        subprocess.run(["git", "-C", repo, "add", "."], check=True)
        subprocess.run(["git", "-C", repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "x"], check=True)
        up = subprocess.run([os.path.join(BIN, "attest"), "upload", f"http://127.0.0.1:{PORT}/s/{sid}#{ae}", repo, "--allow-dev"], capture_output=True, text=True)
        check(up.returncode == 0, "code uploaded")
        call(PORT, "POST", base + "/question", ao, {"text": "Is chain-of-thought trained on?", "answer_format": {"kind": "yes_no"}})
        ok(PORT, "POST", base + "/question/decision", ae, {"version": 1, "accept": True})
        threading.Thread(target=approver, args=(sid, ae, stop), daemon=True).start()
        for agent in agents:
            print(f"== {agent}")
            open(agent_log, "w").close()
            model = "claude-mock" if agent == "claude-code" else "gpt-mock"
            endpoint = LLM if agent == "builtin" else AGENTS
            ok(PORT, "POST", base + "/models", ae, {"provider": "mock", "model": model, "api_key": "test-key", "mock_endpoint": f"127.0.0.1:{endpoint}", "agent": agent})
            run = None
            for _ in range(240):
                runs = ok(PORT, "GET", base, ae)["runs"]
                if runs and runs[-1]["status"] != "running" and len(runs) == agents.index(agent) + 1:
                    run = runs[-1]
                    break
                time.sleep(0.5)
            check(run is not None, f"{agent}: the run finished")
            entries = trace(PORT, sid, ae, run["id"])
            appr = [e for e in entries if e.get("type") == "approval"]
            errors = [e["content"] for e in entries if e.get("type") == "error"]
            mine = [d for d in decisions if d[0] == agent]
            print(f"   run {run['status']}; errors: {[e[:300] for e in errors][:3]}; outcome: {json.dumps(run.get('outcome'))[:300]}")
            if agent == "builtin":
                check(any(not d[2] and d[1] == "read_file" for d in mine), "builtin: read_file was sent for approval and denied")
                results = [e.get("content", "") for e in entries if e.get("type") == "tool_result"]
                check("The auditee denied this call." in results, "builtin: the model was told it was denied")
                check(not any("not that file" in r for r in results), "builtin: the auditee's reason did not reach the model")
                check(any(e["approved"] for e in appr), "builtin: other calls were approved")
            else:
                seen = [json.loads(l) for l in open(agent_log) if l.strip()]
                check(bool(seen), f"{agent}: the harness reached the model")
                last = max(seen, key=lambda x: len(x["results"]))["results"]
                print("   tool results the model saw:", [r[:90] for r in last])
                check(len(mine) >= 3 and [d[2] for d in mine][:2] == [False, True], f"{agent}: each shell command was sent for approval ({mine})")
                check("TOPSECRET" not in json.dumps(seen) and "denied" in last[0] and "not that file" in last[0], f"{agent}: the denied command didn't run, and the model was told why")
                check("hello readme" in last[1], f"{agent}: the approved command ran")
                if agent == "codex":
                    check(WITHHELD in last[2], "codex: write_stdin, which has no hook, had its result withheld")
                    check(any("without a decision" in e for e in errors), "codex: the trace says a result was withheld")
            check(run["status"] == "awaiting_release" and run["verdict"] is not None, f"{agent}: a verdict was produced ({run['status']}, {errors[:2]})")
            ok(PORT, "POST", f"{base}/runs/{run['id']}/release", ae, {"release": True})
            cert = ok(PORT, "GET", f"{base}/runs/{run['id']}/certificate", ao)
            m = json.loads(cert["signed"]["body"])["manifest"] if "signed" in cert else cert["body"]["manifest"]
            ta = m.get("tool_approval")
            check(ta and ta["denied"] >= 1 and ta["approved"] >= 1 and (ta["withheld"] >= 1) == (agent == "codex"), f"{agent}: the certificate records the decisions ({ta})")
            path = os.path.join(work, f"cert-{agent}.json")
            json.dump(cert, open(path, "w"))
            out = subprocess.run([os.path.join(BIN, "attest"), "verify", path, "--allow-dev"], capture_output=True, text=True)
            check(out.returncode == 0 and "approved each of the agent's tool calls" in out.stdout, f"{agent}: the verifier reports it")
        ok(PORT, "POST", base + "/tool-approval", ae, {"enabled": False})
        check(ok(PORT, "GET", base, ao)["tool_approval"] is False, "approval can be turned off")
        for agent in [a for a in agents if a != "builtin"]:
            # Same agent again with approval off: a new model proposal starts a new run.
            open(agent_log, "w").close()
            n = len(ok(PORT, "GET", base, ae)["runs"])
            before = len(decisions)
            ok(PORT, "POST", base + "/models", ae, {"provider": "mock", "model": "claude-mock" if agent == "claude-code" else "gpt-mock", "api_key": "test-key", "mock_endpoint": f"127.0.0.1:{AGENTS}", "agent": agent, "note": "again"})
            for _ in range(240):
                runs = ok(PORT, "GET", base, ae)["runs"]
                if len(runs) > n and runs[-1]["status"] != "running":
                    break
                time.sleep(0.5)
            r = runs[-1]
            errs = [e.get("content", "")[:300] for e in trace(PORT, sid, ae, r["id"]) if e.get("type") == "error"]
            print(f"   {agent} again: {r['status']} {json.dumps(r.get('outcome'))[:200]} errors={errs[:3]}")
            seen = json.dumps([json.loads(l) for l in open(agent_log) if l.strip()])
            check(r["status"] == "awaiting_release" and len(decisions) == before and "TOPSECRET" in seen and WITHHELD not in seen,
                  f"{agent} without approval: runs every call unasked ({r['status']}, {len(decisions) - before} decisions, {seen[:600]})")
            ok(PORT, "POST", f"{base}/runs/{r['id']}/release", ae, {"release": False})
        print("ALL APPROVAL CHECKS PASSED")
    except SystemExit:
        print(open(log).read()[-4000:])
        raise
    finally:
        stop.set()
        for p in procs:
            p.kill()


if __name__ == "__main__":
    main()
