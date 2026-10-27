### Changed: a scan whose every target does not resolve completes with each target skipped

- When every target of a scan job is a name that does not resolve, the command now completes (partial) with the refused-target list (reason `unresolvable`, `refused_targets_total`) instead of failing with "invalid scan target: N of N targets refused". Mixed refusals (a denied or invalid target among them) still fail. The platform already handles the old failed form, so sensor and platform versions stay independent.
