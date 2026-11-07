"""Tiny local-only HTTP target for a safe ReconFlow smoke test."""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    server_version = "ReconFlowLocalDemo/1.0"
    sys_version = ""

    def do_GET(self):
        if self.path == "/health":
            body = b'{"status":"ok"}'
            content_type = "application/json"
        elif self.path == "/robots.txt":
            body = b"User-agent: *\nDisallow:\n"
            content_type = "text/plain"
        else:
            body = b"<!doctype html><title>ReconFlow local demo</title><h1>Local test target</h1><a href='/health'>health</a>"
            content_type = "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


class QuietHTTPServer(HTTPServer):
    def handle_error(self, request, client_address):
        pass


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=8080)
    args = p.parse_args()
    server = QuietHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"Local-only demo: http://127.0.0.1:{args.port}/  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("stopped")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
