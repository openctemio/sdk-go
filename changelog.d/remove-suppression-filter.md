### Removed: the client-side suppression filter

- `Client.GetSuppressions`, `Client.FilterSuppressedFindings` and `client.SuppressionRule` are removed. Nothing called them, and filtering on a sensor would hide matches from the platform, which decides known false positives itself (rules, triage status, gate) and must see every match to notice when flagged code changes. The wire protocol is unchanged: `GET /api/v2/sensor/suppressions`, the v3 `GetSuppressions` RPC and their types stay for platform compatibility.

### Upgrade notes

- Breaking for a caller of the removed functions: drop the call; the platform already leaves suppressed and decided findings out of its views and gate.
