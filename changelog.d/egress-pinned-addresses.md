### Fixed: a confined port scan reaches its target names' addresses

- A tool that resolves a target name itself through the task forwarder's DNS and dials the address it got (naabu over SOCKS5) was refused (`IP is not a target`) on every connection, so a confined port scan found nothing. The forwarder now admits the addresses an admitted name is pinned to: each address alone (never its range), with the same ports and scope limits as its names, never a metadata or link-local address. Names are still never resolved again, so a rebound DNS answer cannot move a target.

### Behaviour change: a target the confinement kept the tool from reaching is not "done"

- When the forwarder's scope refused every connection a tool made toward a target, the tool host settles that target as failed with the class `egress_refused` (`tool.EgressRefused`, ctis `outcome.EgressRefused`) and the task is at best partial; when it refused every connection of the task, every target the tool reported done is settled so. The task log has one line with the count. `toolhost.Outcome.EgressTally` and `egress.Forwarder.Tally` give the counts per target.

### Upgrade notes

- Platforms must accept the ctis `egress_refused` class (ctis with `outcome.EgressRefused`) before sensors built on this release report it; an older platform reads such a target as unfinished and hands it out again.
