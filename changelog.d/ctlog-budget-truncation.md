### Fixed: a slow crt.sh no longer leaves a Certificate Transparency lookup with no answer

- `pkg/ctlog`: crt.sh could use the whole job budget (each attempt may take 90 s, the job has 100 s), so Cert Spotter was never asked and the lookup failed with the context's error instead of an answer listing the source states. crt.sh now ends early enough to leave Cert Spotter a share of the time (all but at least 25 s or 30 %, at most half), and a lookup whose own context is still live always returns an answer (crt.sh `unavailable`, then Cert Spotter's state).

### Fixed: a Cert Spotter list cut by the page limit is no longer reported ok

- When Cert Spotter still answered a full page after the tenth, the answer read `ok` as if the list were complete, so names beyond it looked as if they had vanished. It is now `too_large` and none of the cut list is used, as the contract says for an answer over a cap.

### Behaviour change: a Retry-After cools a source down for 15 minutes at most

- A source's cool-down after a 429 or a Retry-After is shared by every organization a sensor serves. It was up to 24 hours (the contract's bound); it is now at most 15 minutes, and the `retry_after_s` of the source status is capped to match. The per-source pace is unchanged.
