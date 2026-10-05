#!/usr/bin/env python3
"""http-plaintext: an OpenCTEM tool in Python, with no SDK.

It speaks adapter protocol v1 (docs/adapter-protocol.md): newline-delimited
JSON on stdin and stdout, one task per process. It flags HTTP services that
answer in plaintext, from the target address alone (no network: tier T0).

Standard output is the protocol channel only; diagnostics go to stderr.
"""

import json
import sys

# Must describe exactly what tool.yaml says (the run section aside): the
# runtime trusts the file and refuses a tool that describes itself otherwise.
MANIFEST = {
    "apiVersion": "openctem.io/tool/v1",
    "name": "http-plaintext",
    "version": "0.1.0",
    "description": "Flags HTTP services served without TLS (from the address; no network).",
    "class": "target-scan",
    "tier": "T0",
    "consumes": ["http_service"],
    "produces": ["finding:misconfiguration"],
    "permissions": {"network": "none"},
    "selftest": [{"name": "basic", "task": "testdata/task.json", "expect": "testdata/expect.json"}],
}


def send(msg):
    msg["v"] = 1
    sys.stdout.write(json.dumps(msg, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def run(task):
    for target in task.get("targets", []):
        value = target.get("value", "")
        if value.lower().startswith("http://"):
            send({
                "type": "record",
                "kind": "finding",
                "target": target["ref"],
                "data": {
                    "type": "misconfiguration",
                    "rule_id": "http-plaintext",
                    "title": "Service is served over plaintext HTTP",
                    "severity": "medium",
                    "description": "Traffic to " + value + " is not encrypted.",
                },
            })
        send({"type": "target_status", "target": target["ref"], "status": "done"})
    send({"type": "result", "status": "ok"})


def main():
    started = False
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            print("ignoring a line that is not JSON", file=sys.stderr)
            continue
        kind = msg.get("type")
        if not started:
            if kind != "hello" or 1 not in msg.get("protocol", []):
                print("expected hello with protocol 1", file=sys.stderr)
                return 3
            send({"type": "hello", "protocol": 1, "sdk": {"name": "example-python", "version": "0.1.0"}})
            started = True
        elif kind == "describe":
            send({"type": "manifest", "manifest": MANIFEST})
        elif kind == "validate":
            config = msg.get("task", {}).get("config") or {}
            if config:
                send({"type": "validation", "ok": False,
                      "errors": [{"path": "/config", "message": "the tool takes no configuration"}]})
            else:
                send({"type": "validation", "ok": True})
        elif kind == "run":
            run(msg["task"])
            return 0
        # Anything else (cancel before run, a newer runtime's message) is ignored.
    return 0


if __name__ == "__main__":
    sys.exit(main())
