### Behaviour change: `*.x` in the sensor-local policy covers `x` itself

- A `targets.allow` or `targets.deny` entry `*.x` now covers `x` and every name below it, at any depth. It used to cover only the names below `x`. This matches the platform's scope patterns (api RFC-054 §4.1).
- Allow lists: a policy with `*.example.com` now also admits `example.com`. To keep the apex out, add `example.com` to `targets.deny`.
- Deny lists: `*.example.com` in `targets.deny` now also refuses `example.com`. A policy that relied on the old reading to scan the apex while denying its subdomains must deny the subdomains it means instead.
- Patterns and hosts are compared case-insensitively, without one trailing dot, and in IDNA ASCII form: an upper-case or internationalized entry now matches the names it spells.
