### Added: tool network permission `resolver`

- A target-scan tool may declare `permissions.network: resolver`: DNS questions about its targets only, answered through the sensor's resolvers, and no connection to any host, the targets included. It is the network of a DNS resolution tool that never contacts the target hosts (a passive, T0 step).
- Under network confinement the task's forwarder answers DNS for the admitted targets as it does for `targets`, and refuses every connection (`egress.Scope.DNSOnly`). Targets are admitted against the local policy as for `targets`. The executor network class is `resolver`; `tool.Context.HTTP` reaches nothing.
- The tool descriptor JSON schema accepts `resolver`.
