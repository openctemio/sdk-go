### Added: capability http.identity@1

- `toolhost.CapabilityHTTPIdentity` (`http.identity@1`): a sensor whose tools all run through the tool host advertises it (`ToolRegistry.AddCapabilities`). The tool host sends the job's User-Agent and headers (`OrgHTTPPolicy`, for example a bug-bounty program's required identification) on every request of every tool it runs.
- The platform gates jobs that carry such identification on this capability instead of on the SDK version.
