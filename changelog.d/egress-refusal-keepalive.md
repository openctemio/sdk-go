### Fixed: a request the web scope refuses no longer breaks the connection

- The task forwarder answered a refused request with a 403 and closed the connection. HTTP tools then saw EOF or a reset on kept-alive and pipelined requests and counted them toward their per-host error budget. A few refused templates could make nuclei skip the whole host, allowed paths included.
- A refused request now gets a complete 403 (`X-Openctem-Egress: refused`, `Content-Length`), its body is read and discarded (never sent upstream, at most 1 MiB), and the connection stays open for the next request, which is checked the same way. This applies in clear and on the TLS-terminated path.
- The connection still closes after a refusal that is not a request to this destination (CONNECT, an upgrade, another `Host` or port), a body over 1 MiB, `Expect: 100-continue`, the client's `Connection: close`, and protocol errors and non-HTTP traffic. The absolute-form proxy path keeps one request per connection.
