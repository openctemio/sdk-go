# SDK integration test

This example uses `pkg/client` against a running OpenCTEM API to:

1. send a heartbeat;
2. push findings;
3. push assets;
4. push a combined report (findings and assets);
5. poll for commands.

## Prerequisites

1. An OpenCTEM API you can reach, for example a local development stack from
   [openctemio/openctem](https://github.com/openctemio/openctem)
   (`cd api && make docker-migrate-up && make docker-dev`). See
   https://docs.openctem.io for installation.
2. A sensor API key: in the web console, open **Settings > Sensors**, add a
   sensor and copy its API key (it is shown only once).

## Running the test

From the root of this repository:

```bash
export API_KEY="<sensor API key>"
go run ./examples/integration-test/
```

Flags:

| Flag | Default | Meaning |
|---|---|---|
| `-url` | `http://localhost:8080` | The API base URL (not the web console) |
| `-api-key` | `API_KEY` | The sensor API key |
| `-sensor-id` | none | The sensor id, when the key is not bound to one |
| `-verbose` | `true` | Log every request |

The program prints one line per step and `=== Integration Test Complete ===`
at the end. The client speaks sensor protocol v2 (`/api/v2/sensor/*`).

## Troubleshooting

| Message | Fix |
|---|---|
| `API key required` | Pass `-api-key` or set `API_KEY`. If it is set, `-url` points at the web console or at a proxy that strips the `Authorization` header: point it at the API. |
| `401` / invalid API key | The key is wrong, or the sensor was deleted or its key regenerated. Create or regenerate a key under Settings > Sensors. |
| `connection refused` | The API is not running at `-url`. |
