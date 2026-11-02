### Added: adapt.SourcePacer, an adaptive pace for systems of record

- `pkg/adapt.SourcePacer` paces the requests a collector or an importer sends to one production system it reads (an inventory API such as vCenter, a domain controller, a monitoring server): additive increase per clean window, halving on 429/503/busy answers, failures, or answers three times slower than the source's own baseline, and a hold for its Retry-After.
- Its bounds are in the one table (`adapt.SourcePace`, with the reason for each value): floor 0.2/s, default ceiling 5/s, start at half the ceiling, 10s windows. The caller's ceiling (the lowest configured or policy limit) is never exceeded.
