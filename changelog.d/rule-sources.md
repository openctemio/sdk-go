### Added: rule sources for scan commands

- A scan command may carry `rule_sources` (`both`, the default; `platform`; `tenant`). The executor refuses a command that contradicts itself (platform-only with custom templates, tenant-only without any, an unknown value) and passes the choice to the scanner as `ScanOptions.RuleSources`, also to scanners that run out of process.
- `core.CapabilityRuleSources` (`rule.sources@1`): a sensor whose scanners honor the choice reports it; the platform sends tenant-only jobs only to such sensors.
- `core.TenantRulePrefix`, `core.TenantRuleID`: findings of an organization's own rules carry `tenant:`-prefixed rule ids.

### Security: custom templates are checked on the sensor before they are written

- After the signature check, every nuclei custom template is refused when it has a `code`, `javascript`, `flow`, `file` or `headless` block, a self-contained request, `workflows`, a payload file or a second YAML document (`core.CheckCustomTemplate`). The command fails before any template is written or any scanner runs, whatever the platform signed.
