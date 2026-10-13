### Behaviour change: the sensor admits a command under the platform's politeness keys

- The command poller's per-host politeness uses the keys the platform sent with the command (`host_keys`, the keys it admitted the command under and holds while it runs). A command sent with an empty list (a passive stage, which sends no traffic to the target) is never held back for a busy host. A command from an older platform without `host_keys` is keyed by `pkg/politeness`, the function the platform uses.
- Keys conflict as on the platform: the same host, or an address and a range scan of its /24 (IPv6 /120) bucket; two addresses of one bucket no longer hold each other back, and an address and a range covering it now do.
- Sent keys are bounded (at most 500, each at most 512 bytes). `network_id` in the payload scopes the computed keys of private addresses and names (api RFC-089).
- This ends the claim/hand-back loop seen on live sensors ("its hosts are busy on this sensor"): the sensor no longer refuses work the platform has just offered for a host the two keyed differently.

### Deprecated: `core.HostKey`

- Use `github.com/openctemio/sdk-go/pkg/politeness` (`HostOf`, `Keys`). `HostKey` now returns `politeness.HostOf`: the host of any URL other than a `.git` clone URL is the host alone (was `host/first-path-segment` for paths of two or more segments), and a scheme-less `host/path` is the host.
