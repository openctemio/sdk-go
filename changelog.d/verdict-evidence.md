### Added: evidence builders and retest verdicts with evidence (CTIS 1.6)

- The SDK speaks CTIS 1.6 (`pkg/ctis` re-exports `Endpoint`, `WebLocation`, `EvidenceItem` and the ctis evidence builders).
- `tool.HTTPExchange(req, reqBody, resp, respBody, match...)` builds an `http_exchange` evidence item:
  - it keeps the exchange raw and marks the sensitive values (authorization and cookie headers, credential parameters) in `sensitive[]`, without masking them;
  - a body over 64 KiB keeps a window around the first match, and the match offsets follow the window;
  - `content_sha256` covers the full capture.
- Tools can emit CTIS 1.6 endpoints: `Emitter.Endpoint`, the `endpoint` record kind of the adapter protocol, and `endpoints[]` in exec-profile output (CTIS and every importer format). A tool declares `endpoint` in `produces`, and the runtime checks each endpoint as CTIS (an undeclared one is quarantined, an invalid one refused).
- `tool.Evidence(kind, label, data)` builds an item of a kind CTIS does not know yet.
- `RetestContext.Report(item, tool.VerdictReport{...})` reports a verdict with up to five evidence items and the `template_digest` of the check that ran. `tool.RetestVerdict` carries both. Exec and adapter tools send them on the `verdict` message.
- The runtime checks verdict evidence again: too many items, an invalid item or an unreadable digest make the verdict `unverifiable`. Every item is marked again (`ctis.MarkSensitive`).
- Conformance: every capability suite fails a tool whose finding evidence is not valid CTIS, or leaves a sensitive header value unmarked.

### Upgrade notes

- **A networked tool's `fixed` on a finding now needs the attempt's HTTP exchange.** The runtime keeps `fixed` only when the verdict carries an `http_exchange` evidence item whose response arrived; otherwise the verdict is `unverifiable`. Tools without network (code scanners) and asset retests are unchanged. Report retest verdicts with `ctx.Report` and the exchange. A sensor should bump to this release together with the evidence its retest tools emit.
- `tool.Emitter` gained `Endpoint` and `tool.RetestContext` gained `Report`. Only the runtime implements them, so a tool needs no change; a test double that implements either interface must add the method. `tool.RetestVerdict` is no longer comparable with `==`, because it holds evidence.
- `ctis.SchemaVersion` is `1.6`. Reports keep validating at every older version.
