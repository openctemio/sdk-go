# Analyst playbooks

A playbook (`openctem.io/playbook/v1`) tells the analyst harness (`pkg/analyst`) how to work one kind of job:
instructions, steps, the tools it may use (only ever a subset of the job's signed grant), the evidence it must cite
and its budgets (never above the grant). The platform pins a playbook by digest in the job; the same file runs on the
platform's analyst pool and on an organization's own worker.

- `web-vuln-triage/playbook.yaml`: triage of a web application finding (`triage.v1`), small model tier, one probe tool.

Format reference and design: openctem `api/docs/rfcs/RFC-133-ai-analyst-harness.md`.
