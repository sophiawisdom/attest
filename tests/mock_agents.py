"""Scripted model for the jailed harnesses (Claude Code, Codex, pi), speaking
Anthropic's Messages API and OpenAI's Responses API, streamed.

    python3 tests/mock_agents.py PORT LOG

Every conversation runs the same shell commands, one per turn: read
/repo/secret.txt, read /repo/README.md, (Codex only: type into a process
with write_stdin, which has no pre-tool hook), write the verdict file, then
stop. Each request's tool results are appended to LOG as JSON lines.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, LOG = int(sys.argv[1]), sys.argv[2]
STEPS = ["cat /repo/secret.txt", "cat /repo/README.md", "STDIN", """printf '{"answer":"yes"}' > /work/verdict.json"""]


def sse(events):
    return "".join(f"event: {e}\ndata: {json.dumps(d)}\n\n" for e, d in events).encode()


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        tools = [t.get("name") for t in body.get("tools", []) if isinstance(t, dict)]
        harness = "claude-code" if "Bash" in tools else "codex" if "exec_command" in tools else "pi" if "bash" in tools else "none"
        steps = [s for s in STEPS if s != "STDIN" or harness == "codex"]
        if "/messages" in self.path:
            results = [b for m in body.get("messages", []) if isinstance(m.get("content"), list) for b in m["content"] if b.get("type") == "tool_result"]
            seen = [r.get("content") if isinstance(r.get("content"), str) else json.dumps(r.get("content")) for r in results]
        else:
            results = [i for i in body.get("input", []) if isinstance(i, dict) and i.get("type") == "function_call_output"]
            seen = [r.get("output") if isinstance(r.get("output"), str) else json.dumps(r.get("output")) for r in results]
        with open(LOG, "a") as f:
            f.write(json.dumps({"harness": harness, "results": seen}) + "\n")
        n = len(results)
        call = None
        if tools and n < len(steps):
            cmd = steps[n]
            if harness == "codex":
                call = ("write_stdin", {"session_id": 4242, "chars": "id\n"}) if cmd == "STDIN" else ("exec_command", {"cmd": cmd})
            elif harness == "claude-code":
                call = ("Bash", {"command": cmd, "description": "step"})
            else:
                call = ("bash", {"command": cmd})
        text = "done"
        if "/messages" in self.path:
            ev = [("message_start", {"type": "message_start", "message": {"id": f"msg_{n}", "type": "message", "role": "assistant", "model": body.get("model"), "content": [], "stop_reason": None, "usage": {"input_tokens": 10, "output_tokens": 1}}})]
            if call:
                ev += [("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "tool_use", "id": f"toolu_{n}", "name": call[0], "input": {}}}),
                       ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": json.dumps(call[1])}})]
            else:
                ev += [("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
                       ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": text}})]
            ev += [("content_block_stop", {"type": "content_block_stop", "index": 0}),
                   ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "tool_use" if call else "end_turn"}, "usage": {"output_tokens": 5}}),
                   ("message_stop", {"type": "message_stop"})]
        else:
            if call:
                item = {"type": "function_call", "id": f"fc_{n}", "call_id": f"call_{n}", "name": call[0], "arguments": json.dumps(call[1]), "status": "completed"}
            else:
                item = {"type": "message", "id": f"msg_{n}", "role": "assistant", "status": "completed", "content": [{"type": "output_text", "text": text, "annotations": []}]}
            resp = {"id": f"resp_{n}", "object": "response", "status": "completed", "model": body.get("model"), "output": [item], "usage": {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15}}
            ev = [("response.created", {"type": "response.created", "response": {**resp, "status": "in_progress", "output": []}}),
                  ("response.output_item.added", {"type": "response.output_item.added", "output_index": 0, "item": {**item, "arguments": ""} if call else item}),
                  ("response.output_item.done", {"type": "response.output_item.done", "output_index": 0, "item": item}),
                  ("response.completed", {"type": "response.completed", "response": resp})]
        data = sse(ev)
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
