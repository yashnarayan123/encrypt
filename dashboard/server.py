"""Dashboard HTTP server: JSON API + the single self-contained page.

Standard library only (http.server + json + threading): no Flask, no CDN,
fully offline. One Session per server process, every mutation under a
threading.Lock so overlapping clicks (or a double-pressed guided demo)
cannot corrupt state. Binds 127.0.0.1 only.

API (all POST bodies are JSON; every response is JSON):
  GET  /api/state          full snapshot (never contains the key)
  POST /api/send    {cmd}  GCS transmits ARM|LAND|GOTO|RTL|DISARM
  POST /api/jam     {on}   jam toggle (jammed wires record but don't deliver)
  POST /api/mode    {mode, bits}   fresh session on ECB|CBC|GCM x 128|256
  POST /api/reset   {}     fresh session, same mode/bits
  POST /api/replay  {idx}  attacker replays recording idx unchanged
  POST /api/splice  {}     attacker splices newest header + seen DISARM
  POST /api/ivflip  {idx}  attacker seq-rewrite on recording idx
  POST /api/blockflip {idx} attacker Task-3 block flip on recording idx
  GET  /                   the dashboard page (dashboard/static/index.html)
  GET  /results/img_comparison.png   Task-3 image-leak figure (optional view)
"""

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from dashboard.session import Session

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_session = Session()  # one demo session per server process
_lock = threading.Lock()  # every session mutation takes this lock


def _send_json(handler, obj, status=200):
    """Reply with a JSON object (UTF-8, no caching of API state)."""
    body = json.dumps(obj).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


def _read_json(handler):
    """Parse a JSON POST body ({} when empty); raise ValueError if broken."""
    length = int(handler.headers.get("Content-Length") or 0)
    if not length:
        return {}
    try:
        return json.loads(handler.rfile.read(length).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("bad JSON body: %s" % exc)


class Handler(BaseHTTPRequestHandler):
    """Routes: static page, one PNG, and the /api/* JSON actions."""

    server_version = "DroneDemo/1.0"  # plain Server header, nothing fancy

    def log_message(self, *args):  # keep the terminal readable during demos
        pass

    def do_GET(self):
        """Serve the page, the snapshot API, or the comparison PNG."""
        if self.path == "/":
            self._serve_file(os.path.join(STATIC_DIR, "index.html"),
                             "text/html; charset=utf-8")
        elif self.path == "/api/state":
            with _lock:
                _send_json(self, _session.snapshot())
        elif self.path == "/results/img_comparison.png":
            self._serve_file(os.path.join(PROJECT_DIR, "results",
                                          "img_comparison.png"),
                             "image/png")
        else:
            _send_json(self, {"error": "unknown path"}, status=404)

    def do_POST(self):
        """Run one action under the session lock; always answer with JSON."""
        try:
            body = _read_json(self)
        except ValueError as exc:
            _send_json(self, {"error": str(exc)}, status=400)
            return
        action = self.path
        try:
            with _lock:
                result = _dispatch(action, body)
        except (KeyError, IndexError, ValueError) as exc:
            _send_json(self, {"error": "%s: %s" % (type(exc).__name__, exc)},
                       status=400)
            return
        with _lock:
            snap = _session.snapshot()
        snap["result"] = result
        _send_json(self, snap)

    def _serve_file(self, path, content_type):
        """Send a static file, or 404 JSON when it is missing."""
        if not os.path.isfile(path):
            _send_json(self, {"error": "file not found"}, status=404)
            return
        with open(path, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _dispatch(action, body):
    """Map one API path to Session calls. Raises KeyError on bad paths."""
    global _session
    if action == "/api/send":
        if body.get("cmd") not in ("ARM", "LAND", "GOTO", "RTL", "DISARM"):
            raise ValueError("unknown command (buttons send the five)")
        return {"sent": _session.gcs_send(body["cmd"])["n"]}
    if action == "/api/jam":
        return {"jam": _session.toggle_jam(body.get("on", True))}
    if action == "/api/mode":
        _session = Session(mode=body.get("mode", "ecb"),
                           bits=int(body.get("bits", 128)))
        return {"mode": _session.mode, "bits": _session.bits}
    if action == "/api/reset":
        _session = Session(mode=_session.mode, bits=_session.bits)
        return {"mode": _session.mode, "bits": _session.bits}
    if action == "/api/replay":
        return _session.replay(int(body["idx"]))
    if action == "/api/splice":
        return _session.splice()
    if action == "/api/ivflip":
        return _session.iv_flip(int(body["idx"]))
    if action == "/api/blockflip":
        return _session.block_flip(int(body["idx"]))
    raise KeyError("unknown action %r" % action)


def run(host="127.0.0.1", port=8077):
    """Start the dashboard (localhost only) and print its URL."""
    server = ThreadingHTTPServer((host, port), Handler)
    print("Drone attack dashboard at http://%s:%d/  (Ctrl-C to stop)"
          % (host, port))
    server.serve_forever()


if __name__ == "__main__":
    run()
