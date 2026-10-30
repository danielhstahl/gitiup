#!/usr/bin/env python3
"""Redirect every request to a decoy origin, and keep a list of what arrived there.

A credential that leaves the machine it was configured for is the failure this pair of
servers exists to catch (giti-g5c.5). One process, two ports:

    git-decoy.py [origin_port] [decoy_port]

Both are ephemeral when the arguments are 0 (or omitted), and the bound ports are printed
on stdout as `"<origin_port> <decoy_port>"`, which is what the Rust tests wait for and
then read.

* **the origin** answers every request — smart-HTTP ref discovery, a bucket `GET`, a forge
  API call — with `302 Found` and a `Location:` on the decoy, at the same path. This is a
  server that moved, or one that an attacker has pointed at somewhere else: the *shape*
  is what matters. It records nothing; the decoy does the recording, because the
  question is what arrived *there*.

* **the decoy** records every request that reaches it — method, path, and any
  `Authorization` (and `X-Auth`, and the `Cookie` a browser-style client would replay) —
  and answers `403`. Nothing on gitiup's side is supposed to *want* what the decoy
  serves; the decoy is a tripwire. Its recordings are read back with
  `GET /__gitiup_arrivals__`, which returns a JSON list and is deliberately not recorded
  as an arrival itself (or reading the tripwire would set it off). Add `?find=TEXT` to
  get one plain-text line per arrival whose path or credential headers contain `TEXT`
  — the shape a test asserts on without needing a JSON parser.

The control matters as much as the tripwire: a decoy that records nothing would make
every "no token arrived" assertion pass for the wrong reason. So the fixture records a
`CONTROL` marker on start-up — one arrival whose `authorization` is
`gitiup-control-<port>` — and the suite's first assertion is that the control arrived.
A body that cannot see its own control has a broken decoy, not a clean one.
"""

import http.server
import json
import os
import sys
import threading
import urllib.error
import urllib.request

STATUS = int(os.environ.get("GIT_DECOY_STATUS", "403"))

RECORDED_HEADERS = ("authorization", "x-auth", "x-goog-oauth-token", "cookie", "host")

arrivals = []
lock = threading.Lock()


def _snapshot():
    with lock:
        return list(arrivals)


def _record(handler, path, origin):
    """Note one request, keeping only the headers a leaked credential could ride on.

    Both ports write to the one log, tagged with which of them was asked: "nothing reached
    the decoy" is only a fact when something *did* reach the origin, and the log is what
    tells the two apart.
    """
    seen = {}
    for name in RECORDED_HEADERS:
        value = handler.headers.get(name)
        if value is not None:
            seen[name] = value
    entry = {
        "method": handler.command,
        "origin": origin,
        "path": path,
        "headers": seen,
    }
    with lock:
        arrivals.append(entry)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("[git-decoy] " + (fmt % args) + "\n")

    def _drain_body(self):
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

    def _send(self, status, reason, body, extra=None):
        self.send_response(status, reason)
        self.send_header("Content-Type", "application/json" if body.startswith(b"{") else "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            # A client that hung up after the status is not our error.
            pass


class OriginHandler(Handler):
    """The endpoint that moved: every answer is a redirect to the decoy."""

    def redirect(self):
        self._drain_body()
        _record(self, self.path, "origin")
        target = os.environ["GIT_DECOY_BASE"] + self.path
        self._send(
            302,
            "Found",
            b'{"error": "moved", "to": %s}' % json.dumps(target).encode(),
            {"Location": target, "X-Gitiup-Origin": "redirecting"},
        )

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = do_PATCH = redirect


class DecoyHandler(Handler):
    """The tripwire: record what arrived, then refuse."""

    def refuse(self):
        self._drain_body()
        if self.path.startswith("/__gitiup_arrivals__"):
            # Reading the tripwire is not the tripwire going off.
            _, _, needle = self.path.partition("?find=")
            if needle:
                lines = []
                for entry in _snapshot():
                    haystack = entry["path"] + " " + " ".join(entry["headers"].values())
                    if needle in haystack:
                        # METHOD ORIGIN PATH CREDENTIAL: four fields, none of which can be
                        # empty, so a caller can split on whitespace without a parser. The
                        # credential is the value of whichever credential header arrived,
                        # or `-`.
                        auth = (
                            entry["headers"].get("authorization")
                            or entry["headers"].get("x-auth")
                            or entry["headers"].get("x-goog-oauth-token")
                            or "-"
                        )
                        # Squashed to one field: the line is split on whitespace by the
                        # suite, and a credential with a space in it ("Bearer x") would
                        # otherwise cut the value off before the part that matters.
                        auth = "_".join(auth.split())
                        lines.append(
                            "%s %s %s %s"
                            % (entry["method"], entry["origin"], entry["path"], auth)
                        )
                self._send(200, "OK", ("\n".join(lines) + "\n").encode())
                return
            self._send(200, "OK", json.dumps(_snapshot()).encode())
            return
        _record(self, self.path, "decoy")
        self._send(
            STATUS,
            "Forbidden",
            b'{"error": "forbidden", "note": "this is a decoy origin"}',
            {"X-Gitiup-Decoy": "1"},
        )

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = do_PATCH = refuse


def serve(port, handler):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


if __name__ == "__main__":
    origin_port = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    decoy_port = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    origin = serve(origin_port, OriginHandler)
    decoy = serve(decoy_port, DecoyHandler)
    origin_port = origin.server_address[1]
    decoy_port = decoy.server_address[1]
    # Set after binding, because the ports are what the arguments said only when the
    # arguments were not 0.
    os.environ["GIT_DECOY_BASE"] = "http://127.0.0.1:%d" % decoy_port
    # The control: a *real* request to the decoy carrying a recognisable credential, made
    # before the ports are announced. Proof that the recording path works end to end — a
    # decoy that silently dropped headers would otherwise report a clean run forever. A
    # body that cannot find this marker has a broken decoy and must say so rather than
    # report that nothing leaked.
    try:
        urllib.request.urlopen(
            urllib.request.Request(
                "http://127.0.0.1:%d/__gitiup_control__" % decoy_port,
                headers={"Authorization": "Bearer gitiup-control-%d" % decoy_port},
            ),
            timeout=5,
        ).read()
    except urllib.error.HTTPError as error:
        # The decoy answers 403, which is the point of it: what matters is that the
        # credential reached the recording path, not that the answer was friendly.
        error.read()
    print("%d %d" % (origin_port, decoy_port), flush=True)
    threading.Event().wait()
