### Added: one definition of the per-host politeness keys (`pkg/politeness`)

- New nested module `github.com/openctemio/sdk-go/pkg/politeness` (standard library only, tagged `pkg/politeness/vX.Y.Z`): which hosts a scan job touches and when two jobs touch the same host. A name, the host of a URL or a service, an address with the marker of its /24 (IPv6 /120) bucket, and a range with one key per bucket each have a key; an address and a range scan of its bucket conflict, two addresses of one bucket do not.
- Network context (api RFC-089): with a network id, the keys of private, shared, loopback and link-local addresses and of names end in `#<network>`, so overlapping private ranges at two sites are two sets of hosts; public addresses are never scoped to a network. A network id that cannot be read leaves the keys global.
- The platform imports this module so it computes the same keys it holds and sends with a job (api RFC-090). The sensor runtime moves onto it in a follow-up change.
