### Added: sensor protocol v3 transport (gRPC over mTLS, Connect/HTTPS fallback)

- A paired (key-bound) sensor negotiates protocol v3 when the platform's v2 hello lists `transport_v3` (openctem api RFC-059): gRPC over mutual TLS with a 7-day client certificate issued for the sensor's own key (renewed at two thirds of its lifetime, pinned to the platform's sensor CA), then the HTTPS binding (RFC 9421 signatures) when gRPC fails at the transport level (unreachable, handshake, HTTP/2 refused, reset, unimplemented), then protocol v2. An identity refusal never falls back. gRPC is probed again every 30 minutes; three consecutive transport failures renegotiate.
- `SENSOR_TRANSPORT=auto|grpc|https|v2` (default auto). Bearer-key sensors stay on v2.
- v3 sits under the v2 client as a round tripper: retries, the outbox and segmented, idempotent uploads are unchanged, so a lost connection mid-upload still stores the report once.
- The control stream pushes the doorbell (work waiting, cancels, pause) to `core.Doorbell.Handle`: a job starts within a second instead of at the next heartbeat. The heartbeat reports the binding and the fallback reason.
- New: `client.EnableTransportV3`, `StartTransport`, `TransportStatus`, `SetControlEventHandler`, `ParseTransportMode`; `sensorsig.Signer.TLSKey`; `protov2.Hello.TransportV3`; `pkg/sensorproto/v3` (generated, the platform's proto); `conformance.FakePlatform.EnableV3` (both bindings) for sensor tests.

### Security: the paired identity directory is a protected path of the tool sandbox

- No tool may read the identity directory (the signing key, the protocol v3 client certificate and pinned CA).
