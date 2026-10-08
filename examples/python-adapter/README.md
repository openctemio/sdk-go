# A tool in Python, with no SDK

`http_plaintext.py` is a complete OpenCTEM tool in plain Python, using only the
standard library. It speaks adapter protocol v1
([docs/adapter-protocol.md](../../docs/adapter-protocol.md)) and flags HTTP
services that are served without TLS. It decides from the target address
alone, so it needs no network (tier T0).

- `tool.yaml` is the manifest the sensor trusts: what the tool consumes and
  produces, its permissions, its self-test fixture, and how to start it.
- `testdata/task.json` and `testdata/expect.json` are the self-test fixture: a
  task, and the normalized CTIS report it must produce.

To check it the way a sensor will run it:

```sh
go run github.com/openctemio/sdk-go/cmd/openctem tool test examples/python-adapter
```

To install it on a sensor, copy the directory into one of the
`SENSOR_ADAPTER_DIRS`. The directory must be owned by root or the sensor user,
and not writable by others.
