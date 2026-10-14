### Added: pkg/source fetches one commit of a repository for a platform code scan

- `source.Fetcher.Fetch(ctx, ctis source.Repository, *Credential)` fetches exactly the requested commit, read-only, into a private `0700` directory under the scan workspace and returns a `Checkout` (`Remove` when the scan is done).
- Hardening in one place:
  - HTTPS only, to the platform-named host pinned to an address the SSRF guard accepted (`http.curloptResolve`), with no redirects;
  - no hooks, submodules, filters or system or global git configuration;
  - symbolic links checked out as plain files;
  - `transfer.fsckObjects`, and a check that the checkout is the requested commit;
  - a time limit and a size limit on disk (`ErrTooLarge`).
- The credential reaches git only as an HTTP header scoped to the clone URL, in git's environment: never in argv, the checkout or a scanner's environment.
- `AllowPrivate` lets a tenant's own sensor reach an internal SCM on a private address. Loopback, link-local (cloud metadata), CGNAT and reserved ranges are always refused. `CAFile` trusts an internal SCM's private CA. `Proxy` sends the fetch through an HTTPS proxy.

### Added: code-scan jobs fetch their repository source

- A scan command whose payload carries `source` (a ctis `source.Repository`) is a code-scan job. The executor fetches exactly that commit into the first scan-target root (a sensor without scan roots refuses such jobs), scans the checkout, reports on the repository the platform named with the source's branch and commit as a full scan, and removes the checkout. A full scan that found nothing still reports, so the platform can mark fixed findings.
- When the source names a credential, the executor asks the platform for it for this command only: `client.SourceCredential`, `POST /api/v2/sensor/commands/{id}/source-credential` under the lease epoch, v2 HTTPS (protocol v3 does not carry it). `sensorkit` wires it.
