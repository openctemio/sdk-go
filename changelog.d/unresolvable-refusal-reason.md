### Changed: a name that does not resolve is refused as unresolvable, not denied by policy

- A target the local policy's `targets.allow` list cannot match because the name does not resolve is now reported with the refusal reason `unresolvable` (rule `targets.allow`, with the lookup failure kind), also for lookup-only jobs. It was reported as `denied_by_policy`. The name is still never handed to a tool.
- `denied_by_policy` stays for names and addresses that resolve outside `targets.allow` or match `targets.deny`. A job whose every name is unresolvable now completes per target instead of being refused.
