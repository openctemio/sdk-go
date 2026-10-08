### Security: a tool no longer receives another tool's credentials from the environment

- Every tool task got every bundled tool's environment namespace: `TRIVY_*`, `SEMGREP_*` (incl. `SEMGREP_APP_TOKEN`), `PDCP_*`, `NUCLEI_*`, `DOCKER_HOST`, and others. That included a program the operator installed from outside the project. A tool, or a hostile template it loads, could read another tool's credentials.
- `core.ScannerEnvironFor(tool, extra...)` passes a namespace only to the tool it belongs to. The tool host uses it: a compiled-in tool gets its own namespace, and an operator-installed tool gets none (its credentials come from its manifest, in the run message).
- Unchanged:
  - variables the caller passes;
  - names the operator allows (`OPENCTEM_SDK_SCANNER_ENV_ALLOW`, `core.SetScannerEnvAllowlist`);
  - inherit mode;
  - the legacy `core.ExecuteScanner` path.
- Upgrade note: an operator-installed tool that read a vendor variable from the sensor's environment must declare it as a credential, or the operator must allow the name explicitly.
