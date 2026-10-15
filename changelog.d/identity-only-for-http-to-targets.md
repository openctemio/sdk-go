### Fixed: the job's identification goes only to tasks that send HTTP to their targets

- The tool host gave every task of an identification-carrying job the organization's User-Agent and headers, including tasks it exempts: a DNS resolver, passive subdomain sources behind the egress proxy, a port scan.
  - A tool that checks the identification itself refused those tasks ("cannot send the job's identification").
  - A tool requesting through `Context.HTTP`, or an exec tool passing `{{http.user_agent}}` / `{{http.headers:-flag}}`, sent the program's identification to third-party sources.
- A task that sends no HTTP to its targets now gets none of it: `Task.Identity` is nil, and its http settings are built without the organization's User-Agent and headers. The organization's TLS rule still applies. Tasks that do send HTTP to their targets are unchanged: the identification reaches every request, or the task is refused.
- On a target-reaching tool, only `scan.ports`, `discover.hosts` and `resolve.dns` are exempt. `discover.subdomains`, `lookup.rdap` and `lookup.asn` are no longer exempt on such a tool, because it could serve them over HTTP to the targets. Passive tools stay exempt by their network class.
- New `tool.Manifest.SendsHTTPToTargets(capability)`: the rule the tool host applies, exported so a sensor can check the same thing outside the tool host.
