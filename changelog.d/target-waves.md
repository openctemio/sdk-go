### Added: run a list tool in waves of whole hosts, releasing each wave's hosts as it ends

- `core.PlanWaves(targets, network, maxWaves)` cuts a target list into at most `maxWaves` waves of whole hosts (`politeness.Group`): every target of one host is in one wave, waves are balanced by target count and keep the targets' order.
- `core.RunWaves(ctx, targets, network, maxWaves, fn, done)` runs `fn` once per wave, one after the other, and settles each wave's targets when its run returns (`done`, or the job's `TargetDone` when nil). The local queue frees those hosts at once and reports them as `released_keys`, so the next tool of a pipeline starts on them while later waves run.
- For tools that report no per-target end while they run (nuclei runs every template over every host and its output gives no "host finished" signal); a tool that streams per-target results keeps calling `TargetDone` as each one ends.
- Needs ctis with `politeness.Group`.
