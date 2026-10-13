### Security: the task forwarder enforces the job's web scope

- On a sandbox that confines the network, a task with a web scope has every connection read as HTTP by its forwarder (`egress.Scope.Web`, set by the tool host from `tool.Task.WebScope`): TLS is terminated with the forwarder's per-task authority, each request (redirects included) is checked with `webscope.Scope.Allows` as the server reads its path, and a request outside the scope is refused with a 403, recorded and never sent. Non-HTTP traffic to a target of such a task is refused.
- A tool whose own requests do not follow the scope (a template scanner) can now take web-scoped jobs when it runs confined.
- The conformance kit's `vuln.templates` suite checks a tool that declares `features.web_scope` with `/.env` denied.
- `webscope.Scope.Allows` refuses a path a server that drops path parameters reads as denied (`/;/admin`, `/x/..;/admin`): both readings, with and without parameters, must pass. `CleanPath` refuses a dot segment with parameters and a control character.
