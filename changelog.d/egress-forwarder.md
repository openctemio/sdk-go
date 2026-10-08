### Added: pkg/sensorkit/egress, the per-task forwarder; the scope check records every destination

- `egress.Forwarder` serves HTTP CONNECT, absolute-form HTTP and SOCKS5 on a listener the caller gives it, and answers DNS queries (`AnswerDNS`, `ServeDNS`). For every connection it:
  - checks the destination against the task's `Scope` (admitted names at their pinned addresses, never resolved again; admitted prefixes; vendor hosts at public addresses only; metadata, link-local, multicast and unspecified addresses always refused);
  - applies a token-bucket rate per task and per host;
  - records the destination, verdict and bytes.

  DNS answers only admitted names; anything else gets NXDOMAIN. Experimental; it is the forwarder of api RFC-060 (per-task network confinement) and RFC-034 (egress profiles).
- `openctem tool test --scope` runs the tool with its proxy variables pointing at a recording forwarder whose scope is the task's targets. A request through the proxy for anything else fails the check and names the destination. A tool that fetched an outside URL used to pass.
