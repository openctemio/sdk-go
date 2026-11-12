### Fixed: crt.sh answers for large domains are no longer cut at 15 seconds

- `pkg/sensorkit`: crt.sh sends its response headers only once the query for a domain is done. On a large domain that takes longer than the 15 s header wait of the general content client, so large organizations always fell back to Cert Spotter, which lists unexpired certificates only. The CT client now waits up to 75 s for the headers, inside its 90 s request bound and the lookup's own budget.
- New: `httpsec.SafeHTTPClientWith(timeout, headerTimeout)`, the SSRF-guarded client with its own header wait. `httpsec.SafeHTTPClient` is unchanged.
