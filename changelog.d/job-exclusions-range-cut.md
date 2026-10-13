### Security: scan jobs carry their exclusions; ranges are cut address by address

- A scan job's payload may carry `exclusions` (addresses, CIDR prefixes, `first-last` ranges): the platform's scope exclusions that touch the job's targets, covered by the job signature (api RFC-088).
- Before any other check, `LocalPolicy.AdmitCommandTargets` walks each range target (at most 2^16 addresses) and leaves out every address that the job's exclusions, `targets.deny` or the built-in deny list covers; the range is replaced by the smallest prefix set of the addresses kept. This also runs on a sensor without a policy file.
- An address target the job excludes is removed (rule `job_exclusions`); a job with nothing left, or a single-target job whose target would be cut, fails; an unreadable exclusion refuses the job.
- New `ScanOptions.ExcludeHosts` hands the exclusions to tools that can skip hosts themselves.

### Behaviour change: a range that overlaps `targets.deny` or the built-in deny list is cut, not refused whole

- Up to 2^16 addresses, such a range now runs on the addresses outside the deny entries. Wider ranges are still refused whole.
