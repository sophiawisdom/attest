"""`attest plaid-link` against a mock Plaid API.

    python3 tests/plaid_link_test.py
"""
import json
import os
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from handoff_e2e import BIN, ROOT, check  # noqa: E402

PLAID, LOCAL = 46791, 46792
seen = {}


class Plaid(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        seen[self.path] = body
        ok_keys = body.get("client_id") == "cid" and body.get("secret") == "sec"
        out = {"error_message": "bad keys", "error_code": "INVALID_API_KEYS"} if not ok_keys else {
            "/link/token/create": {"link_token": "link-production-abc"},
            "/item/public_token/exchange": {"access_token": "access-production-xyz", "item_id": "item1"},
            "/accounts/get": {"accounts": [{"name": "Operating", "type": "depository", "subtype": "checking", "mask": "4321"}]},
        }[self.path]
        data = json.dumps(out).encode()
        self.send_response(200 if ok_keys else 400)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


def main():
    subprocess.run(["cargo", "build", "--offline", "-q", "--manifest-path", os.path.join(ROOT, "Cargo.toml")], check=True)
    threading.Thread(target=ThreadingHTTPServer(("127.0.0.1", PLAID), Plaid).serve_forever, daemon=True).start()
    cli = os.path.join(BIN, "attest")
    env = {**os.environ, "PLAID_CLIENT_ID": "cid", "PLAID_SECRET": "wrong"}
    bad = subprocess.run([cli, "plaid-link", "--no-browser", "--plaid-url", f"http://127.0.0.1:{PLAID}"], env=env, capture_output=True, text=True, timeout=20)
    check(bad.returncode != 0 and "bad keys" in bad.stderr, "wrong Plaid keys are reported")
    env["PLAID_SECRET"] = "sec"
    p = subprocess.Popen([cli, "plaid-link", "--no-browser", "--port", str(LOCAL), "--plaid-url", f"http://127.0.0.1:{PLAID}"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    page = None
    for _ in range(50):
        try:
            page = urllib.request.urlopen(f"http://127.0.0.1:{LOCAL}/").read().decode()
            break
        except OSError:
            time.sleep(0.1)
    check(page and "link-production-abc" in page and "cdn.plaid.com" in page, "the local page runs Plaid Link with the link token")
    check(seen["/link/token/create"]["transactions"]["days_requested"] == 730, "two years of transactions are requested")
    r = urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{LOCAL}/done", data=b"public-production-123", method="POST")).read().decode()
    check("Done" in r, "the page is told it worked")
    out, err = p.communicate(timeout=10)
    check(p.returncode == 0 and "access-production-xyz" in out and "Operating" in out and "4321" in out, "the access token and accounts are printed")
    check(seen["/item/public_token/exchange"]["public_token"] == "public-production-123", "the public token was exchanged")
    print("ALL PLAID-LINK CHECKS PASSED")


if __name__ == "__main__":
    main()
