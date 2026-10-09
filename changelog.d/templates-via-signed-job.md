### Security: custom templates are trusted through the signed job

- The job statement (`jobsig.Statement`) gains `templates`: the SHA-256 of
  every custom template the payload carries, in order. `jobsig.Verify`
  refuses a statement whose list differs from the payload's (new reason
  `templates`, helpers `jobsig.PayloadTemplateDigests` and
  `jobsig.TemplateDigest`).
- When a command's signed job verified, its custom templates run without
  `SENSOR_TEMPLATE_SIGNING_KEYS`: the platform's job signer names a template
  only when its digest is approved in the signer's scope ledger (api
  RFC-040 P2). The executor compares the decoded templates with the
  verified list before writing them. The local `allow_custom_templates`
  gate and the template validation still apply.
- Sensors without signed jobs keep the per-tenant manifest path
  (`SENSOR_TEMPLATE_SIGNING_KEYS`), now a fallback planned for removal.

### Upgrade notes: older SDKs refuse statements with templates

- A sensor on an earlier SDK that verifies signed jobs refuses a statement
  carrying `templates` (unknown field), so jobs with custom templates fail
  on it until it is upgraded. Jobs without custom templates are unchanged.
