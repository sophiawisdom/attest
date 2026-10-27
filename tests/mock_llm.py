"""Scripted OpenAI-compatible chat server for end-to-end tests.

Drives the agent through list_dir -> grep -> read_file -> submit_verdict,
using what the tools actually returned, so the test exercises the real
tool implementations and the conversation format.
"""
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9999


def tool_call(n, name, args):
    return {"id": f"call_{n}", "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}


def respond(messages):
    tool_msgs = [m for m in messages if m.get("role") == "tool"]
    n = len(tool_msgs)
    if n == 0:
        return "Looking at the layout.", [tool_call(n, "list_dir", {"path": ""})]
    if n == 1:
        return "", [tool_call(n, "grep", {"pattern": "chain_of_thought|cot", "case_insensitive": True})]
    if n == 2:
        hit = re.search(r"^([^\s:]+):\d+:", tool_msgs[1]["content"], re.M)
        path = hit.group(1) if hit else "train.py"
        return "", [tool_call(n, "read_file", {"path": path})]
    content = tool_msgs[2]["content"]
    trains = "include_cot = True" in content
    summary = (
        "The training loss includes chain-of-thought tokens: the loss mask is built with CoT enabled in the "
        "training entry point. A comment in the same file addressed to auditors claims the opposite; it was "
        "treated as a red flag."
        if trains
        else "The training entry point masks chain-of-thought tokens out of the loss."
    )
    return "", [tool_call(n, "submit_verdict", {"answer": "yes" if trains else "no", "confidence": 0.8, "summary": summary})]


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        assert self.headers.get("authorization") == "Bearer test-key", "api key not forwarded"
        assert body["messages"][0]["role"] == "system"
        assert {t["function"]["name"] for t in body["tools"]} >= {"list_dir", "grep", "read_file", "submit_verdict"}
        text, calls = respond(body["messages"])
        out = {
            "id": "mock",
            "model": body["model"] + "-2026-10-01",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": text, "tool_calls": calls}, "finish_reason": "tool_calls"}],
            "usage": {"prompt_tokens": 1000, "completion_tokens": 50},
        }
        data = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("openai-organization", "org-mock-auditee")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


HTTPServer(("127.0.0.1", PORT), H).serve_forever()
