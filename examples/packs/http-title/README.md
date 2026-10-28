# http-title: a sample third-party tool pack

One Python tool, standard library only, that implements `probe.http@1`: it fetches the root page of an HTTP service
and reports its status code, server header and title. It is the shape of a pack written outside OpenCTEM
([docs/tool-packs.md](../../../docs/tool-packs.md)):

- `http-title.py` is the only code the author writes (`run(ctx, task)`);
- `openctem_tool.py` speaks adapter protocol v1 for it (written by `openctem tool init --kind python`);
- `tool.yaml` is the tool's contract (kept in its JSON form so Python reads it without PyYAML);
- `pack.yaml` makes it a pack: versioned, built, signed and delivered like a first-party pack.

The tool reaches its target only through `ctx.connect`, which goes through the sensor's forwarder when the task is
confined: a destination that is not a target of the task is refused there, whatever the tool asks for.

```bash
openctem tool validate .                    # pack.yaml, tool.yaml and the rules between them
openctem tool test --capability --scope .   # self-test, the probe.http suite and the scope check
openctem tool run . --target http://127.0.0.1:8080@http_service
```
