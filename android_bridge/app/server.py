from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json

PAGE = (
    "<!doctype html><html><head><meta charset='utf-8'>"
    "<title>Android Bridge</title></head>"
    "<body style='font-family:system-ui;margin:3rem'>"
    "<h1>Android Bridge — No device paired</h1>"
    "</body></html>"
).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, content_type, body):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            body = json.dumps({"status": "ok", "paired": False}).encode("utf-8")
            self._send(200, "application/json", body)
        elif self.path in ("/", "/index.html"):
            self._send(200, "text/html; charset=utf-8", PAGE)
        else:
            self._send(404, "text/plain; charset=utf-8", b"Not found")

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8791), Handler).serve_forever()
