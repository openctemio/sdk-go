### Security: confined tool tasks reach only their targets, through their own forwarder

- Where the sandbox confines the network (`executor.Config.ConfineNetwork`), the tool host starts a forwarder (`pkg/sensorkit/egress`) for every task whose manifest network is not `none`. Its sockets live in a task directory no task can read. The scope follows the manifest's network:
  - `targets`: the admitted targets, names at the addresses the local policy admitted (`core.LocalPolicy.AdmittedAddrs`), never resolved again;
  - `vendor`: the vendor hosts at public addresses;
  - `egress-proxy`: any public address.

  Every destination is recorded in `Outcome.Egress`. Each refusal is a warning in the task's command log.
- sensorkit turns confinement on by default: `SENSOR_SANDBOX_NETWORK=auto` (where user namespaces are available; otherwise a warning), `required` (refuse to start without it; for shared sensors) or `off`. `openctem tool run|test` do the same (`OPENCTEM_SANDBOX_NETWORK`), and `--scope` reports every destination the task's forwarder refused.
- The forwarder now refuses the cloud metadata addresses outside link-local (`168.63.129.16`, `100.100.100.200`, `fd00:ec2::254`). It also gained `Scope.AnyPublic` and `ServeDNSStream`.
- DNS for an admitted name: A and AAAA come from the scope. Other record types (CNAME, MX, TXT, NS, ...) are asked of the sensor's upstream resolver (`Forwarder.Upstream`, `egress.UpstreamDNS`) and passed back only when the answer matches the question. An unadmitted name is never asked upstream.
- A confined task with a forwarder also gets `OPENCTEM_EGRESS_PROXY` (`executor.EnvEgressProxy`), the relay's proxy URL, for wrappers whose tool takes a proxy flag rather than the proxy variables.
- Upgrade notes:
  - A tool that dials raw sockets instead of honouring the proxy variables gets "network unreachable" when confined.
  - A sensor container needs a seccomp profile that allows user namespaces for confinement; without one it runs as before, with a warning.
