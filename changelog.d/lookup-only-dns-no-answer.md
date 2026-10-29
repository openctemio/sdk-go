### Behaviour change: a scan job whose every target does not resolve completes per target

- At the sensor-local policy's admission, a scan job whose every refused target is a name that does not resolve now completes without running, with each name in `metadata.refused_targets` (reason `unresolvable`, `dns` `name_gone` or `resolver_failed`) and one outcome per name, instead of failing as a whole. The platform can then settle each name on its own. No tool sees any of the names; a job with any other refusal still fails.

### Added: lookup-only DNS jobs report a name without an answer instead of refusing it

- A job naming the lookup-only capability `resolve.dns` checks a name that does not resolve against the domain deny list and, with `targets.allow` set, the allowed domains only, and reports it per target as `unresolvable`; a name outside the allowed domains is refused as `denied_by_policy`. Every capability that connects to its targets keeps refusing a name whose addresses cannot be checked. See `docs/SECURITY.md`.
