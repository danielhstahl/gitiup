#!/usr/bin/env python3
"""Refuse every git request — what revoked or expired credentials look like.

An expired credential is dangerous in a specific way: a client that reads "you may
not see this" as "there is nothing here" reports an empty change list instead of a
refusal, and a merge gets gated on an absence. So `gitiup-host` must answer
`PermissionDenied` here, and the conformance suite needs a server that says
nothing but no.

    git-refused.py 8080

The port is printed on stdout (pass 0 for an ephemeral one), which is what the Rust
tests wait for. Every request — smart-HTTP ref discovery, upload-pack,
receive-pack, or a dumb server's file read — gets the same answer:

* status 403, or `GIT_REFUSE_STATUS` if that is set;
* a body that looks like a web server's complaint rather than git's;
* no `WWW-Authenticate`, on purpose: a challenge makes git prompt for a username,
  and "could not read Username" is a different failure from the one under test.
  403 is what an endpoint that *knows* the identity and refuses it answers — an
  expired token, a pulled deploy key, a rotated basic-auth password.
"""

import http.server
import os
import sys

STATUS = int(os.environ.get("GIT_REFUSE_STATUS", "403"))


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("[git-refused] " + (fmt % args) + "\n")

    def refuse(self):
        body = (
            b"<html><body><h1>Forbidden</h1>"
            b"<p>You do not have permission to access this repository.</p></body></html>\n"
        )
        self.send_response(STATUS, "Forbidden")
        self.send_header("Content-Type", "text/html; charset=UTF-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Gitiup-Refused", "expired-credential")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            # git hangs up as soon as it has the status; that is not our error.
            pass

    def do_GET(self):
        self.refuse()

    def do_HEAD(self):
        self.refuse()

    def do_POST(self):
        # Drain the body so a keep-alive client is not left mid-request: a push
        # arrives as a chunked receive-pack POST, which is exactly the call that
        # must be answered with a refusal rather than truncated.
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            while True:
                line = self.rfile.readline().strip()
                if not line:
                    break
                try:
                    size = int(line, 16)
                except ValueError:
                    break
                if size == 0:
                    self.rfile.readline()
                    break
                self.rfile.read(size)
                self.rfile.readline()
        else:
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)
        self.refuse()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(server.server_address[1], flush=True)
    server.serve_forever()
