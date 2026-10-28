#!/usr/bin/env python3
"""http-title: an OpenCTEM tool in Python (standard library only).

A sample of a third-party tool pack (docs/tool-packs.md): the author writes
only this function. openctem_tool.py, next to it, speaks adapter protocol v1
for it; the sensor owns scheduling, scope, the sandbox, retries, result
checks and delivery. Standard output is the protocol channel: use ctx.log.
"""

import re
import ssl
from urllib.parse import urlsplit

import openctem_tool as ot

MAX_BODY = 256 * 1024
TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def fetch(ctx, url):
    """GET the root of url through ctx.connect; returns (status, headers, body)."""
    u = urlsplit(url if "://" in url else "http://" + url)
    host = u.hostname or ""
    port = u.port or (443 if u.scheme == "https" else 80)
    sock = ctx.connect(host, port, timeout=10.0)
    try:
        if u.scheme == "https":
            tls = ssl.create_default_context()
            # A scanner reports what it finds; it does not trust the target.
            tls.check_hostname = False
            tls.verify_mode = ssl.CERT_NONE
            sock = tls.wrap_socket(sock, server_hostname=host)
        authority = host if port in (80, 443) else "%s:%d" % (host, port)
        req = "GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: http-title/0.1\r\nAccept: text/html\r\n\r\n" % authority
        sock.sendall(req.encode("latin-1"))
        data = b""
        while len(data) < MAX_BODY:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
    finally:
        sock.close()
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ", 2) if lines else []
    if len(parts) < 2 or not parts[1].isdigit():
        raise ValueError("not an HTTP response")
    headers = {}
    for line in lines[1:]:
        k, sep, v = line.partition(":")
        if sep:
            headers[k.strip().lower()] = v.strip()
    return int(parts[1]), headers, body


def run(ctx, task):
    for target in task.targets:
        ctx.check()  # stops here when the runtime cancels the task
        try:
            status, headers, body = fetch(ctx, target.value)
        except ConnectionRefusedError as e:
            ctx.failed(target, "refused_by_policy", e)
            continue
        except (OSError, ValueError) as e:
            ctx.failed(target, "target_unreachable", e)
            continue
        props = {"status_code": status}
        if headers.get("server"):
            props["server"] = headers["server"][:256]
        m = TITLE_RE.search(body)
        if m:
            props["title"] = " ".join(m.group(1).decode("utf-8", "replace").split())[:512]
        ctx.asset(target, {"type": "http_service", "value": target.value, "properties": props})
        ctx.done(target)


if __name__ == "__main__":
    raise SystemExit(ot.serve(run))
