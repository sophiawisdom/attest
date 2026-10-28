"""Scripted OpenAI-compatible chat server for end-to-end tests.

For each user turn (the question, or an auditor follow-up) it drives the agent
through list_dir -> grep -> read_file -> submit_verdict, using what the tools
actually returned. A question containing "CLARIFY" gets needs_clarification.
"""
import json
import re
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9999


def tool_call(n, name, args):
    return {"id": f"call_{n}", "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}


def respond(messages):
    last_user = max(i for i, m in enumerate(messages) if m.get("role") == "user")
    tools = [m for m in messages[last_user:] if m.get("role") == "tool"]
    n, uid = len(tools), last_user
    question = messages[1]["content"]
    if "SLOW" in question and n == 0:
        time.sleep(30)  # a run still going when the test needs one
    if "CLARIFY" in question and "Follow-up" not in messages[last_user]["content"] and n == 0:
        return "", [tool_call(f"{uid}_c", "submit_verdict", {
            "answer": "needs_clarification", "confidence": 0.2,
            "summary": "The repository has no single training pipeline.",
            "clarification_request": "Name the training entry point you mean, or ask about all of them."})]
    if "CHOICE" in question:
        return "", [tool_call(f"{uid}_ch", "submit_verdict", {"choice": "option b"})]
    if "PYTHON" in question:
        if n == 0:
            code = ("import os\nsrc = open('/repo/trainer/train.py').read()\n"
                    "print('files:', sorted(os.listdir('/repo')))\nprint('lines:', len(src.splitlines()))\n"
                    "print('include_cot = True' in src)\n"
                    "try:\n    open('/repo/x', 'w')\nexcept OSError as e:\n    print('write blocked:', type(e).__name__)\n"
                    "try:\n    import socket; socket.create_connection(('1.1.1.1', 80), 2)\nexcept Exception as e:\n    print('network blocked:', type(e).__name__)\n")
            return "", [tool_call(f"{uid}_p", "python", {"code": code})]
        out = tools[0]["content"]
        return "", [tool_call(f"{uid}_v", "submit_verdict", {"answer": "yes" if "True" in out else "no", "confidence": 0.9, "summary": "python said: " + out.replace("\n", " | ")})]
    if n == 0:
        return "Looking at the layout.", [tool_call(f"{uid}_0", "list_dir", {"path": ""})]
    if n == 1:
        return "", [tool_call(f"{uid}_1", "grep", {"pattern": "chain_of_thought|cot", "case_insensitive": True})]
    if n == 2:
        hit = re.search(r"^([^\s:]+):\d+:", tools[1]["content"], re.M)
        return "", [tool_call(f"{uid}_2", "read_file", {"path": hit.group(1) if hit else "train.py"})]
    trains = "include_cot = True" in tools[2]["content"]
    summary = ("The training loss includes chain-of-thought tokens. A comment addressed to auditors claims otherwise; treated as a red flag."
               if trains else "The training entry point masks chain-of-thought tokens out of the loss.")
    return "", [tool_call(f"{uid}_3", "submit_verdict", {"answer": "yes" if trains else "no", "confidence": 0.8, "summary": summary})]


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        assert self.headers.get("authorization") == "Bearer test-key", "api key not forwarded"
        assert body["messages"][0]["role"] == "system"
        text, calls = respond(body["messages"])
        out = {
            "id": "mock", "model": body["model"] + "-2026-10-01",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": text, "tool_calls": calls}, "finish_reason": "tool_calls"}],
            "usage": {"prompt_tokens": 1000, "completion_tokens": 50},
        }
        data = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("openai-organization", "org-mock-auditor")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
