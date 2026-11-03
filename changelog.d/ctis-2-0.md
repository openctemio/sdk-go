### Upgrade notes: CTIS 2.0 only; upgrade sensors and connectors together with the platform

- The SDK produces CTIS 2.0 documents only (`github.com/openctemio/ctis/v2`). There is no 1.x support, no alias and no
  v1 fingerprint bridge. **Upgrade sensors and connectors together with the platform**: the minimum platform is the
  first OpenCTEM release that accepts CTIS 2.0 (the CTIS 2.0 switch release); an older platform refuses every
  document of this SDK, and this SDK's results go nowhere until the platform is upgraded.
- Results are sent as `application/vnd.ctis+json; version=2.0` (`sensorproto/v2.MediaTypeCTIS`,
  `ctis.MediaTypeVersioned`); `sensorproto/v2.IsCTISMediaType` accepts any 2.x.
- The platform and sensor contracts moved out of ctis into `github.com/openctemio/contract` v1.0.0 with the same
  package names: replace `github.com/openctemio/ctis/{capability,tooloption,settings,outcome,politeness,edgeprotect,addrscope,source}`
  by `github.com/openctemio/contract/...`.
- A report queued in the outbox by an earlier SDK (a 1.x document) is dropped with a reason when it is delivered.

### Behaviour change: documents carry no platform identifier

- `metadata.id` is the producer's UUIDv7 (`ctis.NewReportID`), stable across retries and restarts of a delivery. The
  client never writes the command id or the delivery (report) id into the document: the binding to the platform's
  command stays in the request URL. A report without a valid id of its own gets one, kept in `V2Progress.DocumentID`.
- The tool runtime names a target's asset by its position (`target-1`, ...), never by the task's target ref, and
  leaves the task id out of the provenance (`toolrt.Provenance.TaskID` is removed). Every asset gets a document-local
  id; ids and refs are never UUID-shaped (a tool's UUID-shaped id is refused).
- Asset values are written in the canonical form of their type (`ctis.CanonicalAssetValue`) by the record checker, the
  SARIF and JSON parsers and the client; a service written `host:port` gets its transport (`/tcp` by default).

### Behaviour change: CTIS 2.0 members across the SDK

- Asset types are the 2.0 ones (`domain_name`, `web_origin`, `service`, `host`, `identity`, `kubernetes_cluster`,
  `ip_range`, ...). Tool manifests, task targets and scaffolds use them; a 1.x name in `consumes`/`produces` is
  refused with the 2.0 name to use.
- Per-target outcomes travel in `metadata.targets` (done, failed with its class, skipped, unfinished) instead of the
  `target_outcomes`, `unfinished_targets` and `failed_targets` properties. `toolhost.UnfinishedTargetsKey` is removed.
  The command result still carries `target_outcomes` (contract `outcome`).
- Every finding names an asset (`asset_ref` required): a finding without one is filed on its target, or on the task's
  only target, else refused. `ctis.CheckFindingAssets` no longer accepts an empty `asset_ref` with one asset.
- `core.LiveHostsReport` reads open ports from service assets linked by `exposes` relationships (2.0) and drops the
  service assets and relationships; `properties.live_by` names the lowest open port.
- `tool.ReportInfoMetadata` has the 2.0 members a tool may set (`channel`, `source_refs`, `coverage_type`, `branch`,
  `profiles`, `started_at`, `ended_at`, `properties`, `extensions`); `id`, `source_ref`, `source_type` and `scope` are
  removed. The runtime's provenance states the capability in `metadata.extensions["io.openctem"].capability`.
- `tool.Issue.Evidence` becomes an `evidence_items` entry of kind `raw_text`; `Issue.CVE` goes to `vulnerability.ids`.
- The fake platform (`pkg/conformance`) accepts CTIS 2.x only, validates every document, refuses a `metadata.id` that
  is not a UUIDv7 or is the command id, and treats a document committed under another delivery id as a retry.
- Plain scan targets without a type get one from their form (`tool.InferTargetType`); a target value without the
  canonical form of its type keeps its findings on an `unclassified` asset.
- The capability contract checks (tool host, conformance kit) leave out the assets the runtime adds for targets.
  Contract v1.0.0 still names some 1.x rule paths (`properties.port`, `properties.status_code`, `properties.live_by`);
  tools keep those opaque properties until the contract module states the 2.0 paths.

### Added: CTIS 2.0 builders

- `tool.Emitter.Relationship` and the `relationship` record kind (adapter protocol, Python helper
  `ctx.relationship`): typed edges between assets of the report.
- `tool.Emitter.Rule` and the `rule` record kind (Python helper `ctx.rule`): the rule catalog (`rules[]`) a tool that
  reports many findings of one rule writes once; findings name it by `rule_ref`.
- `tool.Emit.Service(hostType, host, port, transport, svc)`: a host, its service asset and the `exposes` edge.
- `tool.Target.Transport`, and `Target.Host`/`Port`/`URL` read a service value (`host:port/transport`).
- Tool content releases (`tool.content[]`), rule revisions (`rules[].content_sha256`, `content_path`) and the
  `io.openctem` extension keys pass through the tool runtime; report info is checked against CTIS like a record.

### Security: secret fingerprints only with a producer key

- `pkg/shared/fingerprint` (the SDK's own copy of the recipes) is removed; the SDK uses CTIS recipe v2
  (`github.com/openctemio/ctis/v2/fingerprint`, `ctis-fp/2:`). `core.GenerateSastFingerprint`,
  `core.GenerateScaFingerprint` and `core.GenerateSecretFingerprint` are replaced by `core.SASTFingerprint`,
  `core.SCAFingerprint` and `core.SecretFingerprint(key, file, ruleID, secret)`.
- A secret enters a fingerprint only as HMAC-SHA256(producer key, secret); without a key the fingerprint is empty
  (the platform computes its own). There is no unsalted path. The sensor kit creates the key once per installation in
  its state directory (`secret-fingerprint.key`, 32 random bytes, mode 0600; it never leaves the sensor) and passes it
  to the command executor (`SetSecretFingerprintKey`), the tool host (`Host.SecretFingerprintKey`) and the parsers
  (`ParseOptions.SecretKey`).
- Evidence items `ctis.MarkSensitive` cannot mark completely are dropped, never sent unmarked.
