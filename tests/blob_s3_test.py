#!/usr/bin/env python3
"""Test the host's S3-backed blob store against tests/s3_standin.py.

    cargo build -p attest-host && python3 tests/blob_s3_test.py

Covers: put/get, a get with the local cache wiped (served from S3),
delete-by-tag, reset (new generation; old objects go), cache trimming under
a tiny quota, a daemon restart, and an S3 outage failing puts.
"""
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST_BIN = os.path.join(ROOT, "target", "debug", "attest-host")
S3_PORT, BLOB_PORT, TUNNEL_PORT = 19500, 19502, 19501
failures = 0


def check(cond, what):
    global failures
    print(("  ok: " if cond else "FAIL: ") + what)
    if not cond:
        failures += 1


def blob(op, ident, data=b""):
    s = socket.create_connection(("127.0.0.1", BLOB_PORT), timeout=60)
    s.sendall(bytes([op]) + ident + struct.pack("<Q", len(data)) + data)
    head = b""
    while len(head) < 9:
        c = s.recv(9 - len(head))
        if not c:
            raise IOError("closed")
        head += c
    status, n = head[0], struct.unpack("<Q", head[1:])[0]
    body = b""
    while len(body) < n:
        c = s.recv(n - len(body))
        if not c:
            raise IOError("closed")
        body += c
    s.close()
    return status, body


def ident(tag, n):
    return bytes([tag]) * 8 + n.to_bytes(16, "big")


def s3_stats():
    return json.load(urllib.request.urlopen(f"http://127.0.0.1:{S3_PORT}/_stats"))


def wait_port(port, timeout=20):
    t = time.time()
    while time.time() - t < timeout:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return
        except OSError:
            time.sleep(0.1)
    raise SystemExit(f"port {port} never opened")


def start_host(work, quota_mib):
    log = open(os.path.join(work, "host.log"), "a")
    p = subprocess.Popen(
        [HOST_BIN, "--dev", "--no-forward", "--dev-tunnel", f"127.0.0.1:{TUNNEL_PORT}",
         "--dev-blobs", f"127.0.0.1:{BLOB_PORT}", "--blob-dir", os.path.join(work, "blobs"),
         "--blob-quota-mib", str(quota_mib), "--s3-bucket", "testbucket", "--s3-region", "us-west-2",
         "--s3-endpoint", f"http://127.0.0.1:{S3_PORT}"],
        stdout=log, stderr=log)
    wait_port(BLOB_PORT)
    return p


def stop(p):
    p.terminate()
    try:
        p.wait(5)
    except subprocess.TimeoutExpired:
        p.kill()


def local_size(work):
    total = 0
    for d, _, fs in os.walk(os.path.join(work, "blobs")):
        total += sum(os.path.getsize(os.path.join(d, f)) for f in fs if f != ".generation")
    return total


def wait_until(cond, timeout=10):
    t = time.time()
    while time.time() - t < timeout:
        if cond():
            return True
        time.sleep(0.1)
    return False


def main():
    work = tempfile.mkdtemp(prefix="attest-blob-s3-")
    s3 = subprocess.Popen([sys.executable, "-I", os.path.join(ROOT, "tests", "s3_standin.py"),
                           "--port", str(S3_PORT), "--page", "3"])
    wait_port(S3_PORT)
    host = start_host(work, 1)
    try:
        print("put and get")
        a = os.urandom(1000)
        check(blob(1, ident(1, 1), a) == (0, b""), "put is acknowledged")
        check(blob(2, ident(1, 1)) == (0, a), "get returns it")
        keys = s3_stats()["keys"]
        cur = [k for k in keys if k.endswith("CURRENT")]
        check(len(cur) == 1 and any(k.endswith("0101010101010101/" + ident(1, 1)[8:].hex()) for k in keys),
              "it's in S3 under <prefix>/<generation>/<tag>/<id>, next to CURRENT")

        print("cache wiped")
        shutil.rmtree(os.path.join(work, "blobs", (b"\x01" * 8).hex()))
        before = s3_stats()["get"]
        check(blob(2, ident(1, 1)) == (0, a), "get still works")
        check(s3_stats()["get"] == before + 1, "it came from S3")
        check(os.path.exists(os.path.join(work, "blobs", (b"\x01" * 8).hex(), ident(1, 1)[8:].hex())), "and is cached again")
        check(blob(2, ident(9, 9))[0] == 1, "an unknown blob is 'not found'")

        print("delete by tag")
        for n in range(7):  # more than one list page (page size 3)
            blob(1, ident(2, n), b"x" * 100)
        blob(1, ident(3, 0), b"keep")
        check(blob(3, ident(2, 0)) == (0, b""), "delete-tag is acknowledged")
        check(blob(2, ident(2, 3))[0] == 1, "its blobs are gone locally")
        check(wait_until(lambda: not any("/" + (b"\x02" * 8).hex() + "/" in k for k in s3_stats()["keys"])),
              "and from S3 (across list pages)")
        check(blob(2, ident(3, 0)) == (0, b"keep"), "other tags are untouched")

        print("daemon restart")
        stop(host)
        host = start_host(work, 1)
        check(blob(2, ident(1, 1)) == (0, a) and blob(2, ident(3, 0)) == (0, b"keep"), "blobs survive a daemon restart")

        print("cache trimming under a 1 MiB quota")
        big = [os.urandom(300_000) for _ in range(10)]
        oks = [blob(1, ident(4, n), d)[0] == 0 for n, d in enumerate(big)]
        check(all(oks), "3 MB of puts into a 1 MiB cache all succeed")
        check(local_size(work) <= 1 << 20, f"the local cache stays under its quota ({local_size(work)} bytes)")
        check(all(blob(2, ident(4, n)) == (0, d) for n, d in enumerate(big)), "every blob is still readable")

        print("reset")
        old_cur = [k for k in s3_stats()["keys"] if k.endswith("CURRENT")]
        check(blob(4, ident(0, 0)) == (0, b""), "reset is acknowledged")
        check(blob(2, ident(1, 1))[0] == 1, "earlier blobs are gone")
        check(blob(1, ident(5, 0), b"new") == (0, b"") and blob(2, ident(5, 0)) == (0, b"new"), "new puts work right away")
        check(wait_until(lambda: [k for k in s3_stats()["keys"] if not k.endswith("CURRENT")]
                         == [k for k in s3_stats()["keys"] if (b"\x05" * 8).hex() in k]),
              "the old generation is deleted from S3; the new blob stays")
        check(len(old_cur) == 1, "one CURRENT throughout")

        print("restart after reset")
        stop(host)
        host = start_host(work, 1)
        check(blob(2, ident(5, 0)) == (0, b"new"), "the new generation is picked up from CURRENT")

        print("drop cache (a standby taking over)")
        blob(1, ident(7, 0), b"current")
        cached = os.path.join(work, "blobs", (b"\x07" * 8).hex(), ident(7, 0)[8:].hex())
        check(os.path.exists(cached), "the blob is cached")
        # As if another instance overwrote it in S3 after this cache took it.
        with open(cached, "wb") as f:
            f.write(b"stale")
        check(blob(2, ident(7, 0)) == (0, b"stale"), "a stale cache entry is served before the drop")
        check(blob(5, ident(0, 0)) == (0, b""), "drop-cache is acknowledged")
        check(blob(2, ident(7, 0)) == (0, b"current"), "afterwards the blob comes from S3")
        check(blob(2, ident(5, 0)) == (0, b"new"), "and nothing stored was lost")

        print("S3 errors")
        urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{S3_PORT}/_fail?n=2", method="POST"))
        check(blob(1, ident(6, 0), b"retried") == (0, b""), "two 500s are retried")
        urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{S3_PORT}/_fail?n=50", method="POST"))
        st, msg = blob(1, ident(6, 1), b"lost")
        check(st == 2 and b"S3" in msg, "a put S3 keeps refusing is not acknowledged")
        urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{S3_PORT}/_fail?n=0", method="POST"))
        check(blob(2, ident(6, 1))[0] == 1, "and isn't served from the cache")
    finally:
        stop(host)
        s3.terminate()
        shutil.rmtree(work, ignore_errors=True)
    print("ALL BLOB S3 CHECKS PASSED" if not failures else f"{failures} FAILED")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
