# Sensor settings (SDK)

Generated from the settings registry (`sensorkit.RegisterSDKSettings`); do not edit.
Regenerate with `UPDATE_SETTINGS_DOC=1 go test ./pkg/sensorkit -run TestSettingsDocUpToDate`.
A sensor declares its own settings in the same registry; the platform's
Setup & health checklist shows each one's presence, never its value.

| Setting | Type | Required | Default | Secret | Description |
|---|---|---|---|---|---|
| [`API_URL`](https://docs.openctem.io/sensor/settings#API_URL) | url | yes |  |  | The platform's API URL (not the web UI origin). |
| [`API_KEY`](https://docs.openctem.io/sensor/settings#API_KEY) | string |  |  | yes | The sensor's bearer API key (legacy). Unset: the sensor pairs on first start and signs its requests with its own key (api RFC-052). |
| [`SENSOR_ID`](https://docs.openctem.io/sensor/settings#SENSOR_ID) | string |  |  |  | The sensor's id, when the key is not bound to one. |
| [`SENSOR_NAME`](https://docs.openctem.io/sensor/settings#SENSOR_NAME) | string |  | `sensor-<hostname>` |  | The sensor's name on the platform. |
| [`SENSOR_PROTOCOL`](https://docs.openctem.io/sensor/settings#SENSOR_PROTOCOL) | enum |  | `auto` |  | Sensor protocol (v2; v1 is retired and refused). |
| [`SENSOR_CA_CERT_FILE`](https://docs.openctem.io/sensor/settings#SENSOR_CA_CERT_FILE) | path |  |  |  | PEM file with the platform's private CA (or a TLS-inspecting proxy's CA). |
| [`SENSOR_CA_FINGERPRINT`](https://docs.openctem.io/sensor/settings#SENSOR_CA_FINGERPRINT) | string |  |  |  | SHA-256 fingerprint of the platform's CA certificate (from the install snippet); pins platform TLS to it. API_URL must then use a host name, not an IP address. |
| [`SENSOR_PLATFORM_KEY`](https://docs.openctem.io/sensor/settings#SENSOR_PLATFORM_KEY) | string |  |  |  | Thumbprint of the platform's pairing key (from the install snippet); pairing refuses another key. |
| [`SSL_CERT_FILE`](https://docs.openctem.io/sensor/settings#SSL_CERT_FILE) | path |  |  |  | System trust store file override (read by the Go runtime and the scanners). |
| [`SSL_CERT_DIR`](https://docs.openctem.io/sensor/settings#SSL_CERT_DIR) | path |  |  |  | System trust store directory override. |
| [`SENSOR_STATE_DIR`](https://docs.openctem.io/sensor/settings#SENSOR_STATE_DIR) | path |  | `/var/lib/openctem/state` |  | Local state: the paired identity and signing key (identity/), the renewed API key and the tool cost history. Mount a persistent volume. |
| [`PLATFORM_KEY_AUTORENEW`](https://docs.openctem.io/sensor/settings#PLATFORM_KEY_AUTORENEW) | bool |  | `auto` |  | API key auto-renewal: true, false, or unset (on when the state directory persists). |
| [`SENSOR_MAX_JOBS`](https://docs.openctem.io/sensor/settings#SENSOR_MAX_JOBS) | int |  |  |  | Cap on concurrent jobs, 1-100. Unset: the slots follow CPU, memory and tool costs. |
| [`SENSOR_DRAIN_GRACE`](https://docs.openctem.io/sensor/settings#SENSOR_DRAIN_GRACE) | duration |  | `30s` |  | How long running jobs may finish on shutdown. |
| [`SENSOR_SCANNER_PRIORITY`](https://docs.openctem.io/sensor/settings#SENSOR_SCANNER_PRIORITY) | enum |  | `low` |  | Priority of scanner processes. |
| [`SENSOR_PROTECT_FROM_OOM`](https://docs.openctem.io/sensor/settings#SENSOR_PROTECT_FROM_OOM) | bool |  | `false` |  | Protect the sensor itself from the OOM killer (needs CAP_SYS_RESOURCE). |
| [`SENSOR_TOOLS`](https://docs.openctem.io/sensor/settings#SENSOR_TOOLS) | list |  |  |  | Allowlist of tools the sensor runs (comma-separated). Unset: every installed tool. |
| [`SENSOR_ADAPTER_DIRS`](https://docs.openctem.io/sensor/settings#SENSOR_ADAPTER_DIRS) | string |  |  |  | Directories of operator-installed tools (tool.yaml with its program), separated by the OS path list separator. |
| [`SENSOR_TEMPLATE_SIGNING_KEYS`](https://docs.openctem.io/sensor/settings#SENSOR_TEMPLATE_SIGNING_KEYS) | list |  |  |  | The platform's template-signing public keys (base64 Ed25519); needed for custom templates. |
| [`SENSOR_LOCAL_POLICY`](https://docs.openctem.io/sensor/settings#SENSOR_LOCAL_POLICY) | path |  | `/etc/openctem/sensor-policy.yaml` |  | The sensor-local policy file the network owner installs. |
| [`SENSOR_ALLOWED_RANGES`](https://docs.openctem.io/sensor/settings#SENSOR_ALLOWED_RANGES) | list |  |  |  | Shorthand local policy: allowed target ranges. |
| [`SENSOR_ALLOWED_PORTS`](https://docs.openctem.io/sensor/settings#SENSOR_ALLOWED_PORTS) | list |  |  |  | Shorthand local policy: allowed ports. |
| [`SENSOR_KILL_SWITCH_FILE`](https://docs.openctem.io/sensor/settings#SENSOR_KILL_SWITCH_FILE) | path |  |  |  | A file whose presence stops every job. |
| [`SENSOR_ALLOW_PRIVATE_TARGETS`](https://docs.openctem.io/sensor/settings#SENSOR_ALLOW_PRIVATE_TARGETS) | enum |  |  |  | 1 allows private (RFC 1918 / ULA) targets; the local policy must allow them too. |
| [`OPENCTEM_SDK_ALLOW_PRIVATE_TARGETS`](https://docs.openctem.io/sensor/settings#OPENCTEM_SDK_ALLOW_PRIVATE_TARGETS) | enum |  |  |  | SDK name of the private-target switch. |
| [`OPENCTEM_SDK_SCAN_ROOTS`](https://docs.openctem.io/sensor/settings#OPENCTEM_SDK_SCAN_ROOTS) | list |  |  |  | Directories code scans may read. |
| [`SENSOR_CONTROL_PROXY`](https://docs.openctem.io/sensor/settings#SENSOR_CONTROL_PROXY) | url |  |  | yes | Proxy for platform requests (may carry credentials: presence only). |
| [`SENSOR_CONTENT_PROXY`](https://docs.openctem.io/sensor/settings#SENSOR_CONTENT_PROXY) | url |  |  | yes | Proxy for content downloads (may carry credentials: presence only). |
| [`SENSOR_SCAN_PROXY`](https://docs.openctem.io/sensor/settings#SENSOR_SCAN_PROXY) | url |  |  | yes | Scanner proxy: direct, inherit, or a proxy URL (may carry credentials: presence only). |
| [`OPENCTEM_SDK_SCANNER_PROXY`](https://docs.openctem.io/sensor/settings#OPENCTEM_SDK_SCANNER_PROXY) | url |  |  | yes | SDK name of the scanner proxy setting. |
| [`HTTPS_PROXY`](https://docs.openctem.io/sensor/settings#HTTPS_PROXY) | url |  |  | yes | Environment proxy (may carry credentials: presence only). |
| [`HTTP_PROXY`](https://docs.openctem.io/sensor/settings#HTTP_PROXY) | url |  |  | yes | Environment proxy (may carry credentials: presence only). |
| [`NO_PROXY`](https://docs.openctem.io/sensor/settings#NO_PROXY) | list |  |  |  | Hosts the environment proxy is not used for. |
| [`OPENCTEM_SDK_SCANNER_ENV_ALLOW`](https://docs.openctem.io/sensor/settings#OPENCTEM_SDK_SCANNER_ENV_ALLOW) | list |  |  |  | Extra environment variables scanners inherit. |
| [`OPENCTEM_SDK_SCANNER_INHERIT_ENV`](https://docs.openctem.io/sensor/settings#OPENCTEM_SDK_SCANNER_INHERIT_ENV) | bool |  |  |  | 1 lets scanners inherit the whole environment (not recommended). |
| [`OPENCTEM_SDK_HTTPSEC_ALLOW_PRIVATE`](https://docs.openctem.io/sensor/settings#OPENCTEM_SDK_HTTPSEC_ALLOW_PRIVATE) | bool |  |  |  | Lets SDK HTTP clients reach private addresses. |
| [`OPENCTEM_SDK_HTTPSEC_ALLOW_LOOPBACK`](https://docs.openctem.io/sensor/settings#OPENCTEM_SDK_HTTPSEC_ALLOW_LOOPBACK) | bool |  |  |  | Lets SDK HTTP clients reach loopback addresses. |
| [`SENSOR_SANDBOX`](https://docs.openctem.io/sensor/settings#SENSOR_SANDBOX) | enum |  | `auto` |  | How every tool run is confined: auto (what the host supports), required (refuse to start without every control), off. |
| [`SENSOR_OUTBOX`](https://docs.openctem.io/sensor/settings#SENSOR_OUTBOX) | enum |  |  |  | The durable results outbox (on for a daemon). |
| [`SENSOR_OUTBOX_DIR`](https://docs.openctem.io/sensor/settings#SENSOR_OUTBOX_DIR) | path |  |  |  | Outbox directory. Mount a persistent volume. |
| [`SENSOR_OUTBOX_MAX_BYTES`](https://docs.openctem.io/sensor/settings#SENSOR_OUTBOX_MAX_BYTES) | bytes |  | `1GiB` |  | Outbox size limit. |
| [`SENSOR_OUTBOX_MAX_AGE`](https://docs.openctem.io/sensor/settings#SENSOR_OUTBOX_MAX_AGE) | duration |  | `168h` |  | Outbox age limit. |
| [`SENSOR_OUTBOX_KEY_FILE`](https://docs.openctem.io/sensor/settings#SENSOR_OUTBOX_KEY_FILE) | path |  |  |  | Outbox encryption key file (default <outbox dir>/outbox.key). |
