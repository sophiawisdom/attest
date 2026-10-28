#!/usr/bin/env python3
"""A tiny in-memory S3 stand-in for testing the host's blob store.

Path-style only, and only what attest-host uses: PUT and GET objects,
ListObjectsV2 (prefix, continuation tokens; page size from --page), and
DeleteObjects. Requests must carry a SigV4 Authorization header (not
verified). GET /_stats returns counters as JSON, and POST /_fail?n=N makes
the next N object requests fail with 500 (to test retries and errors).

    python3 tests/s3_standin.py --port 19500 [--page 1000]
"""
import argparse
import json
import re
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from xml.sax.saxutils import escape

objects = {}  # (bucket, key) -> bytes
stats = {"put": 0, "get": 0, "get_miss": 0, "list": 0, "delete": 0, "deleted_keys": 0}
fail = {"n": 0}
lock = threading.Lock()
PAGE = 1000


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def reply(self, code, body=b"", ctype="application/xml"):
        self.send_response(code)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        n = int(self.headers.get("content-length") or 0)
        return self.rfile.read(n) if n else b""

    def parse(self):
        u = urllib.parse.urlsplit(self.path)
        parts = urllib.parse.unquote(u.path).lstrip("/").split("/", 1)
        bucket = parts[0]
        key = parts[1] if len(parts) > 1 else ""
        q = urllib.parse.parse_qs(u.query, keep_blank_values=True)
        return bucket, key, q

    def authorized(self):
        a = self.headers.get("authorization", "")
        if not a.startswith("AWS4-HMAC-SHA256 Credential=") or "Signature=" not in a:
            self.reply(403, b"<Error><Code>AccessDenied</Code></Error>")
            return False
        return True

    def injected_failure(self):
        with lock:
            if fail["n"] > 0:
                fail["n"] -= 1
                return True
        return False

    def do_PUT(self):
        bucket, key, _ = self.parse()
        data = self.body()
        if not self.authorized():
            return
        if self.injected_failure():
            return self.reply(500, b"<Error><Code>InternalError</Code></Error>")
        with lock:
            objects[(bucket, key)] = data
            stats["put"] += 1
        self.reply(200)

    def do_GET(self):
        bucket, key, q = self.parse()
        if bucket == "_stats":
            with lock:
                s = dict(stats, objects=len(objects), keys=sorted(k for _, k in objects))
            return self.reply(200, json.dumps(s).encode(), "application/json")
        if not self.authorized():
            return
        if self.injected_failure():
            return self.reply(500, b"<Error><Code>InternalError</Code></Error>")
        if key == "" and q.get("list-type") == ["2"]:
            prefix = q.get("prefix", [""])[0]
            start = q.get("continuation-token", [""])[0]
            with lock:
                stats["list"] += 1
                keys = sorted(k for (b, k) in objects if b == bucket and k.startswith(prefix) and k > start)
            page, more = keys[:PAGE], len(keys) > PAGE
            xml = "<ListBucketResult><IsTruncated>%s</IsTruncated>" % ("true" if more else "false")
            xml += "".join("<Contents><Key>%s</Key></Contents>" % escape(k) for k in page)
            if more:
                xml += "<NextContinuationToken>%s</NextContinuationToken>" % escape(page[-1])
            xml += "</ListBucketResult>"
            return self.reply(200, xml.encode())
        with lock:
            d = objects.get((bucket, key))
            stats["get" if d is not None else "get_miss"] += 1
        if d is None:
            return self.reply(404, b"<Error><Code>NoSuchKey</Code></Error>")
        self.reply(200, d, "application/octet-stream")

    def do_POST(self):
        bucket, _, q = self.parse()
        data = self.body()
        if bucket == "_fail":
            fail["n"] = int(q.get("n", ["1"])[0])
            return self.reply(200, b"ok", "text/plain")
        if not self.authorized():
            return
        if "delete" not in q:
            return self.reply(400, b"<Error><Code>BadRequest</Code></Error>")
        if not self.headers.get("x-amz-checksum-sha256") and not self.headers.get("content-md5"):
            return self.reply(400, b"<Error><Code>MissingChecksum</Code></Error>")
        keys = [k.replace("&amp;", "&") for k in re.findall(r"<Key>(.*?)</Key>", data.decode())]
        with lock:
            stats["delete"] += 1
            for k in keys:
                if objects.pop((bucket, k), None) is not None:
                    stats["deleted_keys"] += 1
        self.reply(200, b"<DeleteResult></DeleteResult>")


def main():
    global PAGE
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=19500)
    ap.add_argument("--page", type=int, default=1000)
    a = ap.parse_args()
    PAGE = a.page
    ThreadingHTTPServer(("127.0.0.1", a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
