"""Connected services: a session with no code and one custom API.

    python3 tests/connections_e2e.py

The mock API wants a secret header and echoes it back; the agent (mock
model) calls it through http_request. Checks that the credential is added
by the enclave, kept from the model and the auditor, that disallowed
methods are refused, and that the certificate lists the connection.
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from handoff_e2e import BIN, ROOT, call, check, ok, wait_up  # noqa: E402

TUNNEL, BLOBS, PORT, API, LLM = 46501, 46505, 48501, 46590, 46599
SECRET = "s3cret-ledger-key-0123456789"
seen = []


class Api(BaseHTTPRequestHandler):
    def do_GET(self):
        seen.append((self.command, self.path, self.headers.get("x-api-key")))
        ok_key = self.headers.get("x-api-key") == SECRET
        data = json.dumps({"records": [{"invoice": 7, "status": "paid"}], "echo": self.headers.get("x-api-key")} if ok_key else {"error": "no key"}).encode()
        self.send_response(200 if ok_key else 401)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        seen.append((self.command, self.path, self.headers.get("x-api-key")))
        self.send_response(500)
        self.end_headers()

    def log_message(self, *a):
        pass


def main():
    subprocess.run(["cargo", "build", "--offline", "-q", "--manifest-path", os.path.join(ROOT, "Cargo.toml")], check=True)
    threading.Thread(target=ThreadingHTTPServer(("127.0.0.1", API), Api).serve_forever, daemon=True).start()
    work = tempfile.mkdtemp(prefix="attest-conn-")
    log = os.path.join(work, "enclave.log")
    procs = [
        subprocess.Popen([sys.executable, "-I", os.path.join(ROOT, "tests", "mock_llm.py"), str(LLM)]),
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
        base = f"/api/sessions/{sid}"
        conn = {"kind": "http", "name": "ledger", "base_url": f"http://127.0.0.1:{API}", "header_name": "X-Api-Key",
                "header_value": SECRET, "methods": ["GET"], "description": "Our invoicing system."}
        st, v = call(PORT, "POST", base + "/connections", ao, conn)
        check(st != 200, "only the auditee connects services")
        st, v = call(PORT, "POST", base + "/connections", ae, {"kind": "smoke-signals"})
        check(st == 400 and "kind" in v["error"], "an unknown kind is refused")
        st, v = call(PORT, "POST", base + "/connections", ae, {"kind": "slack", "token": "not-a-slack-token"})
        check(st == 400, "a malformed Slack token is refused")
        c = ok(PORT, "POST", base + "/connections", ae, conn)
        check(c["name"] == "ledger" and c["hosts"] == [f"http://127.0.0.1:{API}"] and c["methods"] == ["GET"], "a custom API connects")
        st, v = call(PORT, "POST", base + "/connections", ae, conn)
        check(st == 400 and "already exists" in v["error"], "names are unique")
        aud = ok(PORT, "GET", base, ao)
        check(aud["connections"][0]["name"] == "ledger" and SECRET not in json.dumps(aud), "the auditor sees the connection, not its credential")

        call(PORT, "POST", base + "/question", ao, {"text": "HTTPTOOL: is invoice 7 paid?"})
        ok(PORT, "POST", base + "/question/decision", ae, {"version": 1, "accept": True})
        ok(PORT, "POST", base + "/models", ae, {"provider": "mock", "model": "gpt-mock", "api_key": "test-key", "mock_endpoint": f"127.0.0.1:{LLM}"})
        run = None
        for _ in range(60):
            v = ok(PORT, "GET", base, ae)
            if v["runs"] and v["runs"][0]["status"] == "awaiting_release":
                run = v["runs"][0]
                break
            time.sleep(1)
        check(run is not None, "a run starts with only a connected service, and finishes")
        check(("GET", "/records?year=2026", SECRET) in seen, "the enclave made the request with the credential")
        check(not any(m == "POST" for m, _, _ in seen), "a method the connection doesn't allow never left the enclave")
        trace = ok(PORT, "GET", f"{base}/runs/{run['id']}/trace?after=0", ae)
        tr = json.dumps(trace)
        check("paid" in tr and SECRET not in tr and "[credential]" in tr, "the model saw the response with the echoed credential masked")
        check("allows only GET" in tr, "the model is told the method isn't allowed")
        check(run["verdict"]["answer"] == "yes", "the verdict comes from the API's data")
        ok(PORT, "POST", f"{base}/runs/{run['id']}/release", ae, {"release": True, "details": True})
        cert = ok(PORT, "GET", f"{base}/runs/{run['id']}/certificate", ao)
        m = cert["body"]["manifest"] if "body" in cert else json.loads(cert["signed"]["body"])["manifest"]
        check(not m["has_code"] and m["connections"][0]["name"] == "ledger" and m["connections"][0]["calls"] == 1,
              "the certificate lists the connection and the requests made through it")
        check(SECRET not in json.dumps(cert), "the certificate has no credential")
        path = os.path.join(work, "certificate.json")
        json.dump(cert, open(path, "w"))
        out = subprocess.run([os.path.join(BIN, "attest"), "verify", path, "--allow-dev"], capture_output=True, text=True)
        check(out.returncode == 0 and "connected ledger" in out.stdout and "knows only its host name" in out.stdout,
              "the certificate verifies and the verifier names the connection")
        st, v = call(PORT, "POST", f"{base}/runs/{run['id']}/followup", ao, {"text": "And invoice 8?", "blinded": True})
        check(st == 400 and "blinded" in v["error"], "blinded follow-ups are refused with connected services")
        f = ok(PORT, "POST", f"{base}/runs/{run['id']}/followup", ao, {"text": "And invoice 8?"})
        check(bool(f["run_id"]), "a follow-up continues a run that had only services")
        for _ in range(60):
            if ok(PORT, "GET", base, ae)["runs"][-1]["status"] == "awaiting_release":
                break
            time.sleep(1)
        ok(PORT, "POST", f"{base}/runs/{f['run_id']}/release", ae, {"release": False})
        ok(PORT, "DELETE", base + "/connections/" + str(c["id"]), ae)
        check(ok(PORT, "GET", base, ae)["connections"] == [], "a connection can be removed")
        print("ALL CONNECTION CHECKS PASSED")
    except SystemExit:
        print(open(log).read()[-3000:])
        raise
    finally:
        for p in procs:
            p.kill()


if __name__ == "__main__":
    main()
