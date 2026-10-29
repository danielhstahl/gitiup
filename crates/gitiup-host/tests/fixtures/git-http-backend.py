#!/usr/bin/env python3
"""Serve git repositories over smart HTTP by running `git http-backend` as a CGI.

This is what `gitiup-host`'s HTTP tests use instead of nginx or Apache: the same
CGI contract a real web server implements, in about a hundred lines and with no
dependency beyond a git install.

    GIT_PROJECT_ROOT=/srv/git git-http-backend.py 8080

The port is printed on stdout (pass 0 to get an ephemeral one), which is what the
Rust tests wait for before talking to it.

Three details that matter, because they are exactly what a hand-rolled harness gets
wrong:

* git POSTs its request bodies with `Transfer-Encoding: chunked`, so the body has
  to be de-chunked before `git-http-backend` sees it — otherwise `receive-pack`
  never gets the packfile and every push fails with a truncated stream.
* Once a client has enough refs to send, git gzips its negotiation body and says so
  with `Content-Encoding: gzip`. The CGI contract is a plain body and a
  `CONTENT_LENGTH` that matches it, so this bridge inflates the body and rewrites the
  length. Leave the gzip in and upload-pack reads binary as pkt-lines (`bad line
  length character`), inflate without fixing the length and the CGI reads a truncated
  request — either way the client just sees "the remote end hung up unexpectedly".
  It bites on the *second* fetch into a mirror, the first one with `have` lines, which
  is how a test passes until the store grows.
* Python 3.14 has no `cgi` module (and `http.server.CGIHTTPRequestHandler` died
  with it), so the CGI protocol is implemented directly: build the environment,
  feed stdin, split `Status:`/headers from the response body.

Anonymous pushes additionally need `http.receivepack = true` in the repository's
own config, exactly as with any other git HTTP server; the caller sets that.
"""

import gzip
import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BACKEND = os.environ.get("GIT_HTTP_BACKEND", "git-http-backend")
EXPORT_ALL = os.environ.get("GIT_HTTP_EXPORT_ALL", "1")
# Headers worth passing through from the CGI to the client.
PASSTHROUGH = {
    "content-type",
    "content-length",
    "cache-control",
    "expires",
    "pragma",
    "last-modified",
    "etag",
    "allow",
}


class CgiHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("[git-http-backend] " + (fmt % args) + "\n")

    def read_body(self):
        """The request body, de-chunked if the client chunked it."""
        if self.headers.get("Transfer-Encoding", "").lower().strip() == "chunked":
            body = bytearray()
            while True:
                line = self.rfile.readline().strip()
                if not line:
                    break
                size = int(line.split(b";")[0], 16)
                if size == 0:
                    self.rfile.readline()  # trailing CRLF after the last chunk
                    break
                body += self.rfile.read(size)
                self.rfile.read(2)  # CRLF after each chunk
            return bytes(body)
        length = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(length) if length else b""

    def do_GET(self):
        self.cgi()

    do_POST = do_GET
    do_HEAD = do_GET

    def cgi(self):
        path, _, query = self.path.partition("?")
        body = self.read_body()
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "GATEWAY_INTERFACE": "CGI/1.1",
            "SERVER_PROTOCOL": "HTTP/1.1",
            "SERVER_NAME": str(self.server.server_address[0]),
            "SERVER_PORT": str(self.server.server_address[1]),
            "REMOTE_ADDR": str(self.client_address[0]),
            "REQUEST_METHOD": self.command,
            "SCRIPT_NAME": "/git-http-backend",
            "PATH_INFO": path,
            "QUERY_STRING": query,
            "GIT_PROJECT_ROOT": os.environ.get("GIT_PROJECT_ROOT", os.getcwd()),
            "GIT_HTTP_EXPORT_ALL": EXPORT_ALL,
            "REMOTE_USER": os.environ.get("REMOTE_USER", ""),
        }
        if self.command not in ("GET", "HEAD"):
            env["CONTENT_TYPE"] = self.headers.get("Content-Type", "")
            # git gzips its negotiation body once it has enough refs to send (a mirror's
            # second fetch is the first one with `have` lines, which is how a test passes
            # until the store grows). The CGI contract is a plain body and a
            # CONTENT_LENGTH that matches it: leave the gzip in and upload-pack reads
            # binary as pkt-lines ("bad line length character", and the client sees "the
            # remote end hung up"), inflate without fixing CONTENT_LENGTH and the CGI
            # reads a truncated request.
            if self.headers.get("Content-Encoding", "").strip().lower() in (
                "gzip",
                "x-gzip",
            ):
                body = gzip.decompress(body)
            env["CONTENT_LENGTH"] = str(len(body))
        try:
            proc = subprocess.run(
                [BACKEND],
                input=body,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except OSError as err:
            self.send_error(500, f"cannot run {BACKEND}: {err}")
            return
        out = proc.stdout
        head, separator, payload = out.partition(b"\r\n\r\n")
        if not separator:
            head, separator, payload = out.partition(b"\n\n")
        status = 200
        headers = {}
        for line in head.decode("latin-1").splitlines():
            if not line.strip():
                continue
            key, _, value = line.partition(":")
            key = key.strip().lower()
            if key == "status":
                status = int(value.strip().split(" ", 1)[0])
            else:
                headers[key] = value.strip()
        self.send_response(status)
        for key, value in headers.items():
            if key in PASSTHROUGH:
                self.send_header(key, value)
        if "content-length" not in headers:
            self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    server = ThreadingHTTPServer(("127.0.0.1", port), CgiHandler)
    print(server.server_address[1], flush=True)
    server.serve_forever()
