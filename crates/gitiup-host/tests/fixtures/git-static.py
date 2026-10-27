#!/usr/bin/env python3
"""Serve a directory of files over HTTP — the dumb-HTTP git transport.

A bare repository with `git update-server-info` run on it is readable over any
file server: git fetches `objects/info/packs` and then whole packfiles. That is a
read-only transport (pushing needs `git-http-backend`, see the other fixture), so
`gitiup-host` treats a plain HTTP origin as a read-only store and says so.

    static-git.py /srv/git 8080

The port is printed on stdout (pass 0 for an ephemeral one), which is what the
Rust tests wait for.
"""

import http.server
import os
import sys


class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("[static-git] " + (fmt % args) + "\n")

    def end_headers(self):
        # No caching: a test that pushes and then re-reads must see the push.
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


if __name__ == "__main__":
    directory = os.path.abspath(sys.argv[1])
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    os.chdir(directory)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(server.server_address[1], flush=True)
    server.serve_forever()
