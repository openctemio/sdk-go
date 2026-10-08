"""openctem_tool: write an OpenCTEM tool in Python with the standard library only.

Copy this file next to your tool (``openctem tool init --kind python`` does).
It speaks adapter protocol v1 (NDJSON on stdin/stdout) so the tool only
writes ``run``::

    import openctem_tool as ot

    def run(ctx, task):
        for t in task.targets:
            ctx.asset(t, {"type": "certificate", "value": "..."})
            ctx.done(t)

    if __name__ == "__main__":
        ot.serve(run)

What it does for you:

- the handshake, ``describe`` (from ``tool.yaml``, which the runtime checks
  against the file), ``validate`` (unknown config keys) and ``run``;
- ``cancel``: read on a thread while ``run`` works; ``ctx.canceled`` is set
  and ``ctx.check()`` raises ``Canceled``;
- heartbeats while ``run`` works, so a long target never hits the idle
  timeout;
- records, per-target status, logs, progress and the final result;
- ``ctx.connect(host, port)``: a TCP connection that goes through the task's
  forwarder when the sandbox confines the network (a confined task has no
  other way out), else directly.

Standard output is the protocol channel: print diagnostics to stderr, or use
``ctx.log``.
"""

import json
import os
import socket
import sys
import threading
import time
from urllib.parse import urlsplit

PROTOCOL = 1
HEARTBEAT_SECONDS = 60

# Error classes of the protocol.
INVALID_INPUT = "invalid_input"
TARGET_UNREACHABLE = "target_unreachable"
REFUSED_BY_POLICY = "refused_by_policy"
TRANSIENT = "transient"
RATE_LIMITED = "rate_limited"
AUTH_FAILED = "auth_failed"
PERMISSION_DENIED = "permission_denied"
NOT_FOUND = "not_found"
TOOL_ERROR = "tool_error"


class Canceled(Exception):
    """The runtime asked the task to stop."""


class Target:
    def __init__(self, raw):
        self.raw = raw
        self.ref = raw.get("ref", "")
        self.type = raw.get("type", "")
        self.value = raw.get("value", "")

    def host_port(self, default_port=0):
        """(host, port) of a URL, host:port or host target."""
        v = self.value
        if "://" in v:
            u = urlsplit(v)
            port = u.port or {"https": 443, "http": 80}.get(u.scheme, default_port)
            return u.hostname or "", port
        if v.startswith("["):
            host, _, rest = v[1:].partition("]")
            return host, int(rest[1:]) if rest.startswith(":") else default_port
        if v.count(":") == 1:
            host, _, port = v.partition(":")
            return host, int(port) if port.isdigit() else default_port
        return v, default_port


class Task:
    def __init__(self, raw):
        self.raw = raw
        self.id = raw.get("id", "")
        self.targets = [Target(t) for t in raw.get("targets") or []]
        self.config = raw.get("config") or {}
        self.capability = raw.get("capability", "")
        self.workdir = raw.get("workdir", "")
        self.credentials = {c.get("name"): c.get("value") for c in raw.get("credentials") or []}
        self.retest = raw.get("retest")


class _Wire:
    def __init__(self, out):
        self._out = out
        self._lock = threading.Lock()

    def send(self, msg):
        msg["v"] = PROTOCOL
        line = json.dumps(msg, separators=(",", ":"), default=str)
        with self._lock:
            self._out.write(line + "\n")
            self._out.flush()


class Context:
    """What run() gets: the record channel, status, logs and the network."""

    def __init__(self, wire, task):
        self._wire = wire
        self.task = task
        self.canceled = threading.Event()
        self._reported = set()
        self.any_failed = False

    # Records ------------------------------------------------------------
    def finding(self, target, data):
        self._record("finding", target, data)

    def asset(self, target, data):
        self._record("asset", target, data)

    def dependency(self, target, data):
        self._record("dependency", target, data)

    def endpoint(self, target, data):
        self._record("endpoint", target, data)

    def _record(self, kind, target, data):
        self.check()
        self._wire.send({"type": "record", "kind": kind, "target": _ref(target), "data": data})

    # Per-target status --------------------------------------------------
    def done(self, target):
        self._status(target, "done")

    def failed(self, target, error_class, detail=""):
        self.any_failed = True
        self._status(target, "failed", {"class": error_class, "detail": str(detail)[:256]})

    def skipped(self, target, reason=""):
        self._status(target, "skipped", {"class": TOOL_ERROR, "detail": str(reason)[:256]} if reason else None)

    def _status(self, target, status, error=None):
        ref = _ref(target)
        if ref in self._reported:
            return
        self._reported.add(ref)
        msg = {"type": "target_status", "target": ref, "status": status}
        if error:
            msg["error"] = error
        self._wire.send(msg)

    # Logs and progress --------------------------------------------------
    def log(self, level, msg, **fields):
        self._wire.send({"type": "log", "level": level, "msg": str(msg), "fields": fields})

    def progress(self, done, total, msg=""):
        self._wire.send({"type": "progress", "done": done, "total": total, "msg": msg})

    def heartbeat(self):
        self._wire.send({"type": "heartbeat"})

    def check(self):
        """Raise Canceled when the runtime asked the task to stop."""
        if self.canceled.is_set():
            raise Canceled()

    # Network ------------------------------------------------------------
    def connect(self, host, port, timeout=10.0):
        """A TCP connection to host:port.

        On a confined sensor the task's only way out is its forwarder: the
        connection is made with HTTP CONNECT through it, and a destination
        that is not a target is refused there (ConnectionRefusedError).
        Elsewhere it is a direct connection.
        """
        proxy = os.environ.get("OPENCTEM_EGRESS_PROXY") or os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
        if not proxy:
            return socket.create_connection((host, port), timeout=timeout)
        p = urlsplit(proxy if "://" in proxy else "http://" + proxy)
        s = socket.create_connection((p.hostname, p.port or 8080), timeout=timeout)
        authority = "[%s]:%d" % (host, port) if ":" in host else "%s:%d" % (host, port)
        s.sendall(("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n" % (authority, authority)).encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = s.recv(1)
            if not chunk or len(head) > 65536:
                s.close()
                raise ConnectionError("egress proxy closed the connection")
            head += chunk
        status = head.split(b"\r\n", 1)[0].split()
        if len(status) < 2 or status[1] != b"200":
            s.close()
            raise ConnectionRefusedError("egress refused %s: %s" % (authority, head.split(b"\r\n", 1)[0].decode("latin-1")))
        return s


def _ref(target):
    return target.ref if isinstance(target, Target) else str(target)


def load_manifest(path):
    """tool.yaml as a dict: JSON (valid YAML), or YAML when PyYAML is installed."""
    with open(path) as f:
        text = f.read()
    try:
        return json.loads(text)
    except ValueError:
        pass
    try:
        import yaml  # optional
    except ImportError:
        raise SystemExit("openctem_tool: %s is not JSON and PyYAML is not installed; "
                         "keep tool.yaml in its JSON form (valid YAML) or install PyYAML" % path)
    return yaml.safe_load(text)


def serve(run, manifest_path=None, validate=None, sdk_name="openctem_tool", stdin=None, stdout=None):
    """Serve one task of adapter protocol v1 and return the exit status.

    run(ctx, task) does the work. It may raise Canceled; any other
    exception ends the task failed with tool_error. validate(config), when
    given, returns a list of (json_pointer, message) problems.
    """
    stdin = stdin or sys.stdin
    wire = _Wire(stdout or sys.stdout)
    if manifest_path is None:
        manifest_path = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "tool.yaml")
    manifest = load_manifest(manifest_path)
    described = {k: v for k, v in manifest.items() if k != "run"}
    keys = set(((manifest.get("config") or {}).get("properties") or {}).keys())

    def problems(config):
        out = [("/config/" + k, "unknown key") for k in sorted(set((config or {}).keys()) - keys)]
        if validate:
            out += list(validate(config or {}))
        return out

    started = False
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        kind = msg.get("type")
        if not started:
            if kind != "hello" or PROTOCOL not in (msg.get("protocol") or []):
                print("openctem_tool: expected hello with protocol 1", file=sys.stderr)
                return 3
            wire.send({"type": "hello", "protocol": PROTOCOL, "sdk": {"name": sdk_name, "version": manifest.get("version", "")}})
            started = True
        elif kind == "describe":
            wire.send({"type": "manifest", "manifest": described})
        elif kind == "validate":
            errs = problems((msg.get("task") or {}).get("config"))
            if errs:
                wire.send({"type": "validation", "ok": False, "errors": [{"path": p, "message": m} for p, m in errs]})
            else:
                wire.send({"type": "validation", "ok": True})
        elif kind == "run":
            return _run(wire, stdin, Task(msg.get("task") or {}), run, problems)
    return 0


def _run(wire, stdin, task, run, problems):
    ctx = Context(wire, task)
    errs = problems(task.config)
    if errs:
        wire.send({"type": "result", "status": "failed", "error": {"class": INVALID_INPUT, "detail": "%s: %s" % errs[0]}})
        return 0

    def reader():
        for line in stdin:
            try:
                if json.loads(line).get("type") == "cancel":
                    ctx.canceled.set()
            except ValueError:
                continue

    def beat(stop):
        while not stop.wait(HEARTBEAT_SECONDS):
            ctx.heartbeat()

    threading.Thread(target=reader, daemon=True).start()
    stop = threading.Event()
    threading.Thread(target=beat, args=(stop,), daemon=True).start()
    try:
        run(ctx, task)
        status, error = "ok", None
    except Canceled:
        status, error = "canceled", None
    except Exception as e:  # the tool's own failure, reported as such
        status, error = "failed", {"class": TOOL_ERROR, "detail": ("%s: %s" % (type(e).__name__, e))[:256]}
    finally:
        stop.set()
    if status == "ok" and ctx.canceled.is_set():
        status = "canceled"
    elif status == "ok" and ctx.any_failed:
        status = "partial"
    msg = {"type": "result", "status": status}
    if error:
        msg["error"] = error
    wire.send(msg)
    return 0


if __name__ == "__main__":
    print(__doc__)
