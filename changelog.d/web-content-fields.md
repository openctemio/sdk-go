### Added: probes and crawlers can report web content facts, bounded

- `core.DiscoveredURL` gains `ContentType`, `Params` and `Forms` (field names and a password-field flag, never values); `Parent` is now redacted by `Sanitize`.
- `core.LiveHost` gains `ResponseHeaders` and `CNAMEs`. `core.ResponseHeadersFrom` keeps only HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy and the two CORS allow headers, plus the names and flags of cookies; cookie values and every other header never pass.
- `NewWebForm` and `IsPasswordFieldName` set the password-field flag from field names, for crawlers that do not see input types.
- `DiscoveredURL.Sanitize`, `SanitizeForms`, `SanitizeURLParams` and `SanitizeCNAMEs` bound every value a scanned server chooses (control characters, non-http(s) schemes, oversize values are dropped). Sensors call them before reporting.
