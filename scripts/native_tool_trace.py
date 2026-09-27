"""Opt-in, loopback-only Responses forwarding for synthetic native acceptance.

Requests and responses are forwarded unchanged. The on-disk allowlist consists
only of model/tool names, event types, HTTP status and parse status. No header,
prompt, tool argument, tool result, or error message is recorded.
"""
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re
import threading
from urllib.parse import urlsplit


def identifier(value):
    return value if isinstance(value, str) and re.fullmatch(r"[a-zA-Z0-9_.:/-]{1,160}", value) else None


def tool_names(tools):
    result = []
    for tool in tools if isinstance(tools, list) else []:
        if not isinstance(tool, dict):
            continue
        item = {k: identifier(tool.get(k)) for k in ("type", "name") if identifier(tool.get(k))}
        function = tool.get("function")
        if isinstance(function, dict) and identifier(function.get("name")):
            item["function"] = function["name"]
        if isinstance(tool.get("tools"), list):
            item["tools"] = tool_names(tool["tools"])
        result.append(item)
    return result


class ToolTrace:
    def __init__(self, destination, upstream="https://basil.xin/v1"):
        parsed = urlsplit(upstream)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.query or parsed.fragment:
            raise ValueError("tool trace requires a fixed HTTPS upstream")
        self.destination = destination
        self.upstream = parsed
        self.lock = threading.Lock()
        self.counter = 0
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                if self.path != "/v1/responses":
                    self.send_error(404)
                    return
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 32 * 1024 * 1024:
                    self.send_error(413)
                    return
                body = self.rfile.read(length)
                with owner.lock:
                    owner.counter += 1
                    request_id = owner.counter
                try:
                    decoded = json.loads(body)
                    owner.record({"request": request_id, "event": "request", "model": identifier(decoded.get("model")),
                                  "tools": tool_names(decoded.get("tools"))})
                except (ValueError, UnicodeError, AttributeError):
                    owner.record({"request": request_id, "event": "request_unparsed"})
                connection = http.client.HTTPSConnection(owner.upstream.hostname, owner.upstream.port or 443, timeout=300)
                try:
                    headers = {k: v for k, v in self.headers.items()
                               if k.lower() not in ("host", "connection", "content-length", "transfer-encoding")}
                    connection.request("POST", owner.upstream.path.rstrip("/") + "/responses", body=body, headers=headers)
                    response = connection.getresponse()
                    owner.record({"request": request_id, "event": "http_response", "status": response.status})
                    self.send_response(response.status)
                    for name in ("Content-Type", "Content-Encoding", "Retry-After"):
                        if response.getheader(name):
                            self.send_header(name, response.getheader(name))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    pending = b""
                    while True:
                        chunk = response.read1(65536)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                        self.wfile.flush()
                        pending += chunk
                        while b"\n" in pending:
                            line, pending = pending.split(b"\n", 1)
                            if line.startswith(b"data: "):
                                owner.response_event(request_id, line[6:])
                        if len(pending) > 1024 * 1024:
                            pending = b""  # Do not retain unbounded streamed content.
                except (OSError, http.client.HTTPException):
                    owner.record({"request": request_id, "event": "forwarding_error"})
                    self.close_connection = True
                finally:
                    connection.close()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base_url(self):
        return f"http://127.0.0.1:{self.server.server_port}/v1"

    def start(self):
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def record(self, data):
        with self.lock:
            with self.destination.open("a", encoding="utf-8") as output:
                output.write(json.dumps(data) + "\n")

    def response_event(self, request_id, data):
        try:
            event = json.loads(data)
        except (ValueError, UnicodeError):
            return
        if not isinstance(event, dict):
            return
        kind = event.get("type")
        if kind not in ("response.output_item.added", "response.output_item.done", "response.completed", "response.failed", "error"):
            return
        record = {"request": request_id, "event": kind}
        item = event.get("item")
        if isinstance(item, dict):
            record["item_type"] = identifier(item.get("type"))
            if identifier(item.get("name")):
                record["tool_name"] = item["name"]
        self.record(record)
