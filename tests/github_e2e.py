"""Importing code from GitHub (needs internet).

    GITHUB_TOKEN=... python3 tests/github_e2e.py

With GITHUB_TOKEN (any token that can read sophiawisdom/attest) it also
imports the repository; without one it checks only the refusals.
"""
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from handoff_e2e import BIN, ROOT, call, check, ok, wait_up  # noqa: E402

TUNNEL, BLOBS, PORT = 46401, 46405, 48401


def main():
    subprocess.run(["cargo", "build", "--offline", "-q", "--manifest-path", os.path.join(ROOT, "Cargo.toml")], check=True)
    work = tempfile.mkdtemp(prefix="attest-github-")
    log = os.path.join(work, "enclave.log")
    procs = [
        subprocess.Popen([os.path.join(BIN, "attest-host"), "--dev", "--no-forward", "--dev-tunnel", f"127.0.0.1:{TUNNEL}",
                          "--dev-blobs", f"127.0.0.1:{BLOBS}", "--blob-dir", os.path.join(work, "blobs")],
                         stderr=open(os.path.join(work, "host.log"), "w")),
        subprocess.Popen([os.path.join(BIN, "attest-enclave"), "--dev", "--dev-listen", f"127.0.0.1:{PORT}",
                          "--dev-tunnel", f"127.0.0.1:{TUNNEL}", "--dev-blobs", f"127.0.0.1:{BLOBS}",
                          "--python-dir", os.path.join(work, "no-python")],
                         stderr=open(log, "w")),
    ]
    try:
        wait_up(PORT, log)
        s = ok(PORT, "POST", "/api/sessions", body={})
        sid, ae, ao = s["session_id"], s["auditee_token"], s["auditor_token"]
        path = f"/api/sessions/{sid}/code/github"
        st, v = call(PORT, "POST", path, ao, {"repo": "sophiawisdom/attest"})
        check(st != 200, "only the auditee provides code")
        st, v = call(PORT, "POST", path, ae, {"repo": "../etc"})
        check(st == 400, "a malformed repository name is refused")
        st, v = call(PORT, "POST", path, ae, {"repo": "sophiawisdom/attest"})
        check(st == 400 and "token" in v["error"] and "required" in v["error"], "a token is required (public code needs no enclave)")
        st, v = call(PORT, "POST", path, ae, {"repo": "sophiawisdom/no-such-repo-attest-test", "token": "ghp_not_a_real_token"})
        check(st == 400, "a missing repository or bad token is reported")
        st, v = call(PORT, "POST", path, ae, {"repo": "sophiawisdom/attest", "token": "ghp_not_a_real_token"})
        check(st == 400 and "token" in v["error"], "a bad token is reported")
        token = os.environ.get("GITHUB_TOKEN", "")
        if not token:
            print("ALL GITHUB CHECKS PASSED (no GITHUB_TOKEN: import not tested)")
            return
        v = ok(PORT, "POST", path, ae, {"repo": "sophiawisdom/attest", "ref": "main", "token": token})
        check(v["file_count"] > 10 and len(v["github"]["commit"]) == 40, f"the repository is imported ({v['file_count']} files at {v['github']['commit'][:7]})")
        view = ok(PORT, "GET", f"/api/sessions/{sid}", ae)
        events = [e["text"] for e in view.get("events", [])]
        check(any("sophiawisdom/attest" in t for t in events), "the auditee is told where it came from")
        aud = ok(PORT, "GET", f"/api/sessions/{sid}", ao)
        rec = aud["affidavit"]["record"]
        check(rec["fetched_by_enclave"] and rec["repo_url"] == "https://github.com/sophiawisdom/attest" and rec["git_commit"] == v["github"]["commit"],
              "both sides see the repository and commit the enclave fetched")
        check(aud["status"] != "" and not any(a["action"] == "confirm_affidavit" for a in view["next_actions"]), "no affidavit step")
        print("ALL GITHUB CHECKS PASSED")
    except SystemExit:
        print(open(log).read()[-2000:])
        raise
    finally:
        for p in procs:
            p.kill()


if __name__ == "__main__":
    main()
