### Fixed: the job's identification is handed only to tasks that send HTTP to their targets

- The tool host set `Task.Identity` on every task of an identification-carrying job, including tasks it exempts (a DNS resolver, passive subdomain sources behind the egress proxy, a port scan). A tool that checks the identification itself then refused those tasks ("cannot send the job's identification"), and a tool requesting through `Context.HTTP` would have sent the program's headers to third-party sources.
- `Task.Identity` is now nil for a task that sends no HTTP to its targets. Tasks that do are unchanged: the identification reaches every request, or the task is refused.
- New `tool.Manifest.SendsHTTPToTargets(capability)`: the rule the tool host applies, exported so a sensor checks the same thing on paths outside the tool host.
