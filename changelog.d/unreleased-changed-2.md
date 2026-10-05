### Changed

- **`pkg/ctis` imports `github.com/openctemio/ctis`** (owner decision Q3,
  research 16 G2), pinned to ctis main at `7d7d5ec` (untagged; includes
  ctis#14 secret-snippet masking in `FromSARIF`, ctis#15 recon hardening and
  ctis#16 SARIF suppressions). The hand copy had drifted and the sensor ran
  stale converters. Fixed by the switch:
  - recon reports validate: no scope type `web`, no raw recon type
    (`port`, `url_crawl`) as a capability, IPv6 addresses as `AAAA`
    records, one DNS record per value, hostname-only port results as
    `host` assets, every probe an `http_service`, stable asset IDs and order;
  - `FromSARIF` converts every run (each finding names its run's tool
    when there are several), reads `security-severity` and CVE/CWE tags,
    types Trivy CVEs as `vulnerability` (they were all misconfigurations),
    gives an unknown tool no capabilities (it got `vulnerability, secret`,
    so SAST from an unknown tool could be filed as secret), and gives the
    asset no criticality (it defaulted to `high`; spec 4.1 leaves it to the
    receiver);
  - `NewReport()` stamps schema version `1.3` (was `1.0`);
  - new from the module: `SchemaVersion`, `SchemaURL`, `ParseVersion`,
    `IsCompatibleVersion`, `(*Report).Validate`, `SARIFLogicalLocation`,
    `SARIFReportingReference`.
  The SDK keeps its asset rule on top of the module's `FromSARIF` (options,
  then branch info, then `versionControlProvenance`; results without an
  asset are `ErrNoAssetForFindings`), plus `CheckFindingAssets` and the
  `NormalizeSARIF*` helpers. `scripts/check-ctis-parity.sh` (the
  `ctis-parity` job) now regenerates the aliases and fails when they are
  stale, or when `pkg/ctis` declares a model struct of its own again.
  Bumping CTIS is `go get github.com/openctemio/ctis@<ver>` plus
  `go generate ./pkg/ctis`.
- **Every report the runtime pushes states `coverage_type`** (CTIS spec 4.5:
  an absent value is not `full`; research 16 G4, owner decision Q5). A scan
  command's report is `partial` when the scanner says the run stopped
  part-way (`ScanResult.Error`) or the report lists `failed_targets`, even if
  the parser declared `full`; otherwise a value the parser declared is kept;
  a repository scan (`metadata.branch`) is `partial`; any other completed
  run is `full`. Collector reports keep the collector's value, else
  `partial`. Daemon-mode scan and collect reports follow the same rules.
  The platform's coverage-scoped auto-resolve used to read the missing
  value as `full`; it is being changed to read it as not full, and this
  keeps completed sensor scans eligible after that change.

- `ctis.FromSARIF` carries `properties.tags` from the result and its rule
  into the finding's `tags` (they were dropped), as `github.com/openctemio/ctis`
  does (ctis#12). Tags are deduplicated ignoring case in first-seen order;
  non-string, empty and over-long (more than 128 bytes) entries are skipped; at
  most 50 are kept per finding.
- The SARIF converter keeps one secret-scanner list (gitleaks, betterleaks,
  trufflehog, detect-secrets, or any name containing `secret`) for both the
  finding type and the tool capabilities. Capabilities used to match any name
  containing `leaks`; they now match the same names as the finding type and
  as ctis.
- `scripts/check-ctis-parity.sh` also compares FromSARIF's secret-scanner
  list, tag caps, `sarifTags` / `isSecretTool` bodies and the shared
  betterleaks sample against ctis.
