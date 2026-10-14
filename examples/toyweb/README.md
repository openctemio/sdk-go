# toyweb (scratch proof, not for release)

A toy `dast.web@1` tool used to prove that a new tool needs no platform change
(openctem RFC-092 P0): it fetches each web origin and reports the security
response headers it does not send. Build it statically and install the
directory (binary + `tool.yaml`, root-owned, not writable by others) in a
sensor adapter directory (`SENSOR_ADAPTER_DIRS`):

```sh
CGO_ENABLED=0 go build -o toyweb ./examples/toyweb
go run ./cmd/openctem tool validate examples/toyweb/tool.yaml
```
