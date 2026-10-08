### Added: openctem_tool.py, a Python helper for tools

- `openctem tool init --kind python` writes `openctem_tool.py` next to the tool: one file, standard library only, that speaks adapter protocol v1. The tool writes only `run(ctx, task)`. The helper provides:
  - the handshake, `describe` from `tool.yaml` and `validate`;
  - `cancel`, honoured while `run` works (`ctx.check()`), and heartbeats against the idle timeout;
  - records, per-target status, logs, progress and the result.
- `ctx.connect(host, port)` opens a TCP connection through the task's forwarder when the sensor confines the network (api RFC-060), where a raw socket has no route; elsewhere it connects directly.
- The python scaffold uses the helper. Before, every Python tool re-implemented about 60 lines of protocol and ignored `cancel` while it ran.
