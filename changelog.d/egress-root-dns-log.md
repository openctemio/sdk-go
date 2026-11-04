### Fixed: the egress log names the root DNS query and folds repeated refusals

- A refused query for the root name (sent by a tool's DNS library) is recorded and logged as `.`, not as an empty host. Admission is unchanged: it is still refused.
- A task's log shows one line per distinct refusal (host, port, protocol, reason) with a `count` field and an `(xN)` suffix when it repeated. The cap of 20 lines and the "N more destinations" tail now count distinct destinations.
