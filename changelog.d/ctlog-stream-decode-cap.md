### Security: a hostile Certificate Transparency answer no longer costs gigabytes of memory

- `pkg/ctlog` read a source's whole answer (up to 48 MiB), copied it into a string and decoded the full JSON list before refusing it for having more than 20,000 records, so one crafted 47 MiB answer from a mirror or a compromised source peaked at several GiB of heap on a shared sensor. crt.sh and Cert Spotter answers are now decoded one row at a time and refused (`too_large`) at the first row past the record cap; the 48 MiB byte cap still holds for the whole body.
- An empty 200 answer from crt.sh is a bad answer (`unavailable`, not cached) and no longer "ok, no certificates"; crt.sh answers `[]` when it has none.
