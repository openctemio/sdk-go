### Added: tools receive the organization's source keys from the platform

- A tool whose manifest declares credentials (for one, subfinder's passive
  sources) now asks the platform, once per task and under the command's
  lease, for the keys the job's organization stored for it
  (`POST /api/v2/sensor/commands/{id}/tool-credentials`, v2 HTTPS only;
  `client.ToolCredentials`, `core.ToolCredentialsFrom`). The keys reach the
  tool in the task's run message only, are on the task's redaction list and
  are not kept after the task.
- Precedence per credential name: the organization's key wins; the
  operator's key (`sensorkit.Options.ToolCredentials`) fills a name the
  organization left unset only when the platform allows it (on the
  organization's own sensor, never on a shared sensor). Outside a platform
  job, or with a platform that does not serve the route, the operator's keys
  are used as before. When the platform cannot answer, the task runs with
  neither and its log says so.
- A manifest may declare up to 64 credentials (was 16).
