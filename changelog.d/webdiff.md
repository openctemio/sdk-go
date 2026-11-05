### Added: `pkg/webdiff`, the calibrated differ of path discovery

- `webdiff.Prober` probes candidate paths of one origin for one task: per (directory, shape: bare, slash, `ext:<e>`, dot) it takes baselines of three random names, derives noise bands (length and simhash over the normalised body), and reports a hit only when the answer differs from the baseline, the difference repeats, and, for a directory or a 403, a random child answers like a missing path. It recalibrates after 200 requests or when more than 2 % of differences fail to confirm. Hits carry status, media type, auth state (none, required, redirect_login), labels and evidence (decoded size, 64-bit hash of the normalised body); `webdiff.Endpoint` turns one into a CTIS endpoint with the evidence in `extensions["io.openctem"].response`.
- Gap reasons: `catch_all`, `auth_wall`, `edge_protected`, `throttled`, `blocked`, `unstable_baseline`, `budget`, `hostile_response`, `protocol`, `scope_filtered`.
- The conformance kit gains an `enumerate.web_paths` suite.

### Security

- `pkg/webdiff` never follows a redirect, reads at most 256 KiB of a body, decodes gzip itself with the expansion bounded at 100:1, bounds headers at 64 KiB, gives an exchange a 10 s deadline and the body a minimum rate; an answer that breaks a bound stops the origin. An edge challenge or block is never a signal; 429 and 503 back off and are never a hit. Baselines live for one task only.
- `tool.Context.HTTP` of a task whose web scope carries a request cap (a discovery task) refuses response headers over 64 KiB.
