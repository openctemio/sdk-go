### Added: relay transport for sensors that cannot reach the platform directly (`pkg/relayclient`)

- `relayclient.Transport` is an `http.RoundTripper` placed under the request signer. Each signed v2 request is sealed to the platform's ingest key (`pkg/sealedmsg`) and posted to a sensor relay. The answer comes back on the sensor's relay mailbox, signed by the platform and sealed to the sensor's key, and is returned as the request's response. The rest of the client is unchanged.
- The relay's certificate is checked against its SPKI pin from the pairing bundle (or against `RootCAs`). The sensor's identity key is the TLS client certificate, and the platform-signed ticket goes with every request; `OnTicketRefused` says when to renew it.
- Answers that do not verify, that answer no outstanding request, or that repeat one already delivered are dropped and counted. The relay's `Retry-After` is honoured. Mailbox polls back off with full jitter up to 60 s. A missing answer is `ErrNoResponse`, which callers retry like any lost response.
- Not wired into `sensorkit` yet: the mode selection, the fallback chain and the pairing bundle import come with the platform's relay connector.
