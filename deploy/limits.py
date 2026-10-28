#!/usr/bin/env python3
"""Show or change a running enclave's limits, without a restart.

    HANDOFF_TOKEN=... deploy/limits.py https://1.2.3.4                 # show
    HANDOFF_TOKEN=... deploy/limits.py https://1.2.3.4 --max-sessions 200 --session-memory-mib 2048

The request carries a MAC under the deployment's handoff token (from
attest.env), so TLS isn't checked here: whoever is in the middle can only
see the limits, not change them. A change lasts until the enclave restarts;
to keep it, also put "max_sessions" / "session_memory_mib" in
/etc/attest/host.json, which the enclave reads at boot. Limits only refuse
new work: lowering one never drops a session.
"""
import argparse
import hashlib
import hmac
import json
import os
import ssl
import struct
import sys
import time
import urllib.request


def mac(token, *parts):
    h = hashlib.sha256(b"".join(struct.pack("<Q", len(p)) + p for p in parts)).digest()
    return hmac.new(token.encode(), h, hashlib.sha256).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url", help="the enclave, e.g. https://1.2.3.4")
    ap.add_argument("--max-sessions", type=int)
    ap.add_argument("--session-memory-mib", type=int)
    a = ap.parse_args()
    token = os.environ.get("HANDOFF_TOKEN", "")
    if len(token) < 16:
        sys.exit("set HANDOFF_TOKEN (see attest.env)")
    at = int(time.time() * 1000)
    s = lambda v: b"" if v is None else str(v).encode()
    body = {"at_ms": at, "mac": mac(token, b"attest-limits/1", s(a.max_sessions), s(a.session_memory_mib), str(at).encode())}
    if a.max_sessions is not None:
        body["max_sessions"] = a.max_sessions
    if a.session_memory_mib is not None:
        body["session_memory_mib"] = a.session_memory_mib
    req = urllib.request.Request(a.url.rstrip("/") + "/api/internal/limits", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
            print(json.dumps(json.load(r), indent=2))
    except urllib.error.HTTPError as e:
        sys.exit(f"{e.code}: {e.read().decode(errors='replace')}")


if __name__ == "__main__":
    main()
