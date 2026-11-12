### Fixed: one giant Certificate Transparency row no longer costs hundreds of MiB

- `pkg/ctlog`: the record and byte caps held for an answer, but one row was still read whole: a crt.sh row of tens of MiB of names, or a Cert Spotter issuance with millions of `dns_names`, cost up to several GiB of allocations before the cap was reached. Each row is now capped at 2 MiB (a real row is a few KiB; the contract keeps at most 1000 names of 253 bytes) and an answer with a row over it is `too_large`; crt.sh's names are cut at the contract's 1000 while they are split.

### Fixed: a big domain no longer costs eleven Cert Spotter requests at every lookup

- `pkg/ctlog`: a source that answered `too_large` is remembered per organization, domain and cursor for the cache's lifetime (about 20 hours), so the next lookup does not ask it again; crt.sh is still retried when it failed in a way that may pass. A lookup answered `too_large` by every source is cached as a whole.
- A Cert Spotter list that ends exactly on the last page the limit allows is now `ok`: one more page is asked after the limit, and only a non-empty one makes the list `too_large` (an empty page is the API's only end marker; its page size is not fixed). Lists one page short of the cut were reported `too_large` before.
- The cool-down after a 429 without Retry-After (30 times the configured interval) is now capped at 15 minutes like every other cool-down.

### Fixed: the disk high watermark no longer flaps around its mark

- `pkg/localstore`: once free space fell below the high marks (share of the volume and `HighFreeBytes`), claiming resumes only when free space is 10 % above both, so a volume hovering near 16 GiB free no longer switches claiming on and off at every sweep.
- The 8 GiB cap of the low disk mark applies only to the default share (5 %): an operator's own `Options.MinFreeFraction` is honored in full.
