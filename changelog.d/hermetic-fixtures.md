### Added: hermetic self-test fixtures served by the conformance kit

- A fixture task file may carry a `serve` member (default response, per-path overrides, optional self-signed TLS) and `{{fixture.url}}`, `{{fixture.host}}`, `{{fixture.port}}`, `{{fixture.host_port}}` placeholders in its target values. `openctem tool test` serves it on 127.0.0.1 for the run and normalizes the port in the expected CTIS. The member is read only by the kit and never reaches a sensor or `tool.yaml`.
- `openctem tool init` writes such a fixture for tools that take URLs, services or hosts, so a fresh scaffold's self-test no longer sends traffic to an internet host, and writes a `.gitignore`. The kit runs python tools with `PYTHONDONTWRITEBYTECODE=1`.
