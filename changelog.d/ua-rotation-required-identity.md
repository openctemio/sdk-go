### Security: required identification fails closed

- A job's `http_policy.identification_required` (set by the platform, the organization or a program) makes every HTTP request a task sends to its targets carry the job's identification headers and query parameter. A job that requires it but carries neither, or a task whose tool cannot carry them on a sandbox that does not confine the network, is refused with `refused_by_policy` before the tool starts: no request is sent.
- New capability `http.identity.required@1` (toolhost `CapabilityHTTPIdentityRequired`): a sensor advertises it, with `http.identity@1`, when its tools run through the tool host. The platform gives jobs that require identification only to such a sensor.

### Added: the forwarder carries the identification for tools that cannot

- On a sandbox that confines the network, a tool that cannot put the job's identification on its requests is no longer refused: the task's forwarder guards every connection and sets the headers, the query parameter and each host's User-Agent on every HTTP/1.x request (`egress.Scope.Identity`). Anything else is refused there. The applied report says who carried it (`carrier`).

### Added: User-Agent rotation per run and host

- `http_policy.user_agents` (at most 200) with `user_agent_key` (the run's id), and the sensor owner's `http.user_agents` (policy v1, exclusive with `http.user_agent`). Each target host of a run gets one value, the same for every request of the run (contract `identity.SelectUserAgent`); the winning layer's list is used whole (the owner's over the job's unless locked). The identification headers and query parameter travel with every value.
- `AppliedIdentity` reports `user_agent_pool`, `user_agent_reason` (a tool that cannot set a User-Agent, or takes one per process for hosts with different values), `required` and `carrier`.
- Requires contract `identity` (contract 1.6.0).
