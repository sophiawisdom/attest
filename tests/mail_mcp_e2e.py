"""Connected mailbox (IMAP) and MCP server, with mock servers.

    python3 tests/mail_mcp_e2e.py

Checks that the enclave only sends read-only IMAP commands, decodes mail
for the agent, lists an MCP server's tools for the auditee to choose from,
refuses tools that weren't chosen, and records both in the certificate.
"""
import json
import os
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from handoff_e2e import BIN, ROOT, call, check, ok, wait_up  # noqa: E402

TUNNEL, BLOBS, PORT, IMAP, MCP, LLM = 46601, 46605, 48601, 46691, 46692, 46699
PASSWORD = "app-password-abcd-efgh"
MCP_TOKEN = "mcp-token-0123456789abcdef"
imap_cmds, mcp_calls = [], []

MSG = (b"From: Bank <alerts@bank.com>\r\nTo: cfo@acme.com\r\nSubject: =?utf-8?q?Wire_received?=\r\nDate: Mon, 5 Oct 2026 10:00:00 +0000\r\n"
       b"Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nA wire received: =E2=82=AC250,000 from Globex.\r\n")
HDRS = {1: b"From: Newsletter <news@x.com>\r\nSubject: Hello\r\n\r\n", 2: b"From: Bank <alerts@bank.com>\r\nSubject: Wire received\r\n\r\n"}


class Imap(socketserver.StreamRequestHandler):
    def handle(self):
        w = lambda b: self.wfile.write(b if isinstance(b, bytes) else b.encode())
        w("* OK mock IMAP ready\r\n")
        authed = False
        while True:
            line = self.rfile.readline().decode().rstrip("\r\n")
            if not line:
                return
            tag, _, cmd = line.partition(" ")
            imap_cmds.append(cmd if not cmd.startswith("LOGIN") else "LOGIN")
            verb = cmd.split(" ")[0].upper()
            if verb == "LOGIN":
                authed = PASSWORD in cmd
                w(f"{tag} OK logged in\r\n" if authed else f"{tag} NO [AUTHENTICATIONFAILED] bad password\r\n")
            elif not authed:
                w(f"{tag} NO log in first\r\n")
            elif verb == "LIST":
                w('* LIST (\\HasNoChildren) "/" "INBOX"\r\n* LIST (\\HasNoChildren) "/" "Receipts"\r\n' + f"{tag} OK\r\n")
            elif verb == "EXAMINE":
                w(f"* 2 EXISTS\r\n{tag} OK [READ-ONLY] examined\r\n")
            elif cmd.startswith("UID SEARCH"):
                w(f"* SEARCH 1 2\r\n{tag} OK\r\n")
            elif cmd.startswith("UID FETCH") and "HEADER.FIELDS" in cmd:
                for i, u in enumerate(int(x) for x in cmd.split(" ")[2].split(",")):
                    h = HDRS[u]
                    w(f"* {u} FETCH (UID {u} BODY[HEADER.FIELDS (DATE FROM TO SUBJECT)] {{{len(h)}}}\r\n".encode() + h + b")\r\n")
                w(f"{tag} OK\r\n")
            elif cmd.startswith("UID FETCH"):
                w(f"* 2 FETCH (UID 2 BODY[]<0> {{{len(MSG)}}}\r\n".encode() + MSG + b")\r\n" + f"{tag} OK\r\n".encode())
            elif verb == "LOGOUT":
                w(f"* BYE\r\n{tag} OK\r\n")
                return
            else:
                w(f"{tag} BAD unexpected\r\n")


TOOLS = [
    {"name": "lookup_customer", "description": "Look up a customer by id.", "inputSchema": {"type": "object", "properties": {"id": {"type": "integer"}}}, "annotations": {"readOnlyHint": True}},
    {"name": "delete_customer", "description": "Delete a customer.", "inputSchema": {"type": "object", "properties": {"id": {"type": "integer"}}}, "annotations": {"readOnlyHint": False}},
]


class Mcp(BaseHTTPRequestHandler):
    def do_POST(self):
        msg = json.loads(self.rfile.read(int(self.headers["content-length"])))
        if self.headers.get("authorization") != f"Bearer {MCP_TOKEN}":
            self.send_response(401)
            self.end_headers()
            return
        m = msg.get("method")
        mcp_calls.append((m, self.headers.get("mcp-session-id"), msg.get("params", {}).get("name")))
        if "id" not in msg:
            self.send_response(202)
            self.end_headers()
            return
        if m == "initialize":
            out = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "acme-crm", "version": "1.2"}}
        elif m == "tools/list":
            out = {"tools": TOOLS}
        elif m == "tools/call" and msg["params"]["name"] == "lookup_customer":
            out = {"content": [{"type": "text", "text": f"customer 7: Globex, balance 0, token echo {MCP_TOKEN}"}]}
        else:
            out = None
        reply = {"jsonrpc": "2.0", "id": msg["id"], **({"result": out} if out is not None else {"error": {"code": -32601, "message": "no"}})}
        if m == "tools/list":
            # As an event stream, with a notification first.
            data = (b"event: message\ndata: " + json.dumps({"jsonrpc": "2.0", "method": "notifications/progress", "params": {}}).encode()
                    + b"\n\nevent: message\ndata: " + json.dumps(reply).encode() + b"\n\n")
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
        else:
            data = json.dumps(reply).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
        if m == "initialize":
            self.send_header("mcp-session-id", "sess-1")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


def main():
    subprocess.run(["cargo", "build", "--offline", "-q", "--manifest-path", os.path.join(ROOT, "Cargo.toml")], check=True)
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    threading.Thread(target=socketserver.ThreadingTCPServer(("127.0.0.1", IMAP), Imap).serve_forever, daemon=True).start()
    threading.Thread(target=ThreadingHTTPServer(("127.0.0.1", MCP), Mcp).serve_forever, daemon=True).start()
    work = tempfile.mkdtemp(prefix="attest-mailmcp-")
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
        mail = {"kind": "imap", "name": "mail", "host": "127.0.0.1", "port": IMAP, "tls": False, "username": "cfo@acme.com", "password": "wrong-password"}
        st, v = call(PORT, "POST", base + "/connections", ae, mail)
        check(st == 400 and "refused the login" in v["error"], "a wrong mail password is refused")
        mail["password"] = PASSWORD
        c = ok(PORT, "POST", base + "/connections", ae, mail)
        check(c["kind"] == "imap" and "cfo@acme.com" in c["identity"], "a mailbox connects, identified by its login")

        url = f"http://127.0.0.1:{MCP}/mcp"
        st, v = call(PORT, "POST", base + "/connections/preview", ae, {"kind": "mcp", "url": url, "token": "wrong"})
        check(st == 400 and "401" in v["error"], "an MCP server that refuses the token is reported")
        p = ok(PORT, "POST", base + "/connections/preview", ae, {"kind": "mcp", "url": url, "token": MCP_TOKEN})
        check(p["server"] == "acme-crm 1.2" and [(t["name"], t["read_only"]) for t in p["tools"]] == [("lookup_customer", True), ("delete_customer", False)],
              "the MCP server's tools are listed (from an event-stream reply), with their read-only hints")
        st, v = call(PORT, "POST", base + "/connections", ae, {"kind": "mcp", "name": "crm", "url": url, "token": MCP_TOKEN})
        check(st == 400 and "choose the tools" in v["error"], "the auditee must choose tools")
        m = ok(PORT, "POST", base + "/connections", ae, {"kind": "mcp", "name": "crm", "url": url, "token": MCP_TOKEN, "tools": ["lookup_customer"]})
        check(m["tools"] == ["lookup_customer"] and m["hosts"] == [f"http://127.0.0.1:{MCP}"], "an MCP server connects with the chosen tools")
        aud = json.dumps(ok(PORT, "GET", base, ao))
        check(PASSWORD not in aud and MCP_TOKEN not in aud, "the auditor sees no credentials")

        call(PORT, "POST", base + "/question", ao, {"text": "MAILMCP: did the wire from Globex arrive?"})
        ok(PORT, "POST", base + "/question/decision", ae, {"version": 1, "accept": True})
        ok(PORT, "POST", base + "/models", ae, {"provider": "mock", "model": "gpt-mock", "api_key": "test-key", "mock_endpoint": f"127.0.0.1:{LLM}"})
        run = None
        for _ in range(60):
            v = ok(PORT, "GET", base, ae)
            if v["runs"] and v["runs"][0]["status"] in ("awaiting_release", "failed"):
                run = v["runs"][0]
                break
            time.sleep(1)
        check(run is not None and run["status"] == "awaiting_release", "the run finishes")
        tr = json.dumps(ok(PORT, "GET", f"{base}/runs/{run['id']}/trace?after=0", ae))
        check("Receipts" in tr and "Wire received" in tr, "the agent listed folders and searched")
        check("\\u20ac250,000" in tr or "€250,000" in tr, "the message was decoded for the agent")
        check("customer 7: Globex" in tr and MCP_TOKEN not in tr and PASSWORD not in tr, "the MCP tool answered, with the echoed token masked")
        check("delete_customer" in tr and "no tool named" in tr, "a tool the auditee didn't choose isn't callable")
        verbs = {c.split(" ")[0] if not c.startswith("UID") else " ".join(c.split(" ")[:2]) for c in imap_cmds}
        check(verbs <= {"LOGIN", "LIST", "EXAMINE", "UID SEARCH", "UID FETCH", "LOGOUT"} and all("BODY.PEEK" in c for c in imap_cmds if c.startswith("UID FETCH")),
              f"only read-only IMAP commands were sent ({sorted(verbs)})")
        check(('SEARCH FROM "bank"' in " ".join(imap_cmds)), "the search criteria reached the server")
        check([x for x in mcp_calls if x[0] == "tools/call"] == [("tools/call", "sess-1", "lookup_customer")], "only the chosen tool was called, in the server's session")
        check(run["verdict"]["answer"] == "yes", "the verdict comes from the mail")
        ok(PORT, "POST", f"{base}/runs/{run['id']}/release", ae, {"release": True, "details": True})
        cert = ok(PORT, "GET", f"{base}/runs/{run['id']}/certificate", ao)
        man = cert["body"]["manifest"] if "body" in cert else json.loads(cert["signed"]["body"])["manifest"]
        conns = {c["name"]: c for c in man["connections"]}
        check(conns["mail"]["calls"] == 3 and conns["crm"]["calls"] == 1 and conns["crm"]["tools"] == ["lookup_customer"], "the certificate records both, with their calls and allowed tools")
        path = os.path.join(work, "certificate.json")
        json.dump(cert, open(path, "w"))
        out = subprocess.run([os.path.join(BIN, "attest"), "verify", path, "--allow-dev"], capture_output=True, text=True)
        check(out.returncode == 0 and "MCP server" in out.stdout and "lookup_customer" in out.stdout and "cfo@acme.com" in out.stdout, "the verifier describes both")
        print("ALL MAIL/MCP CHECKS PASSED")
    except SystemExit:
        print(open(log).read()[-3000:])
        raise
    finally:
        for p in procs:
            p.kill()


if __name__ == "__main__":
    main()
