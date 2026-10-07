### Security: jobs can carry a web scope that the SDK enforces

- A job (`ScanCommandPayload.web_scope`, `tool.Task.WebScope`) can carry a web scope (`pkg/webscope`). It names:
  - the hosts a web tool may request (`*.example.com` covers the domain and every name under it);
  - the path prefixes it may request, and the paths it never requests (`deny_paths`);
  - the methods it may use (GET, HEAD and OPTIONS when none are named).
- `tool.Context.HTTP` refuses every request outside the scope, redirects included. The path is checked as the server sees it: decoded, with dot segments resolved. A path with an encoded slash, backslash or NUL is refused.
- A networked tool must declare `features.web_scope` to take a job with a web scope; otherwise the job is refused (`refused_by_policy`). An invalid scope is refused, never ignored, and a scanner that cannot take capability jobs fails such a job.
- Exec-profile tools read the scope from the new `{{task.web_scope_file}}` placeholder.
- The conformance kit's new `crawl.web` and `dast.web` suite fails a tool that requests a denied path, or that does not declare `features.web_scope`.
