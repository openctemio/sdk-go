### Added: content slots — a tool declares its templates, rules and wordlists; tasks get read-only packs

- `tool.yaml` `content:` declares the content a tool reads (api RFC-061), slot by slot:
  - `kind`: a known one (`nuclei-templates`, `semgrep-rules`, `yara-rules`, `vuln-db`, `wordlist`, `signatures`) or a namespaced `x-<vendor>/<kind>`;
  - `format`, `default`, `modes` (default, custom, merge), `selectors`.
- A task carries `content` per slot: packs by `sha256:` digest with the path the sensor's cache resolved. A tool reads them through:
  - `task.ContentPaths(slot)` in Go;
  - `task.content_paths(slot)` in the Python helper;
  - `run.task.content` for adapters;
  - `{{content.<slot>}}` / `{{content.<slot>...}}` in exec argv.
- Isolation:
  - `executor.Config.Private` hides more roots (the content cache) from every task, and `TaskSpec.ReadPaths` grants a task read-only access to exactly its packs;
  - `toolhost.Host.ContentRoot` and `tool.CheckTaskContent` refuse a pack outside the cache, an undeclared slot, an unsupported mode or selector, and a non-digest.
- `openctem tool run --content slot=dir` hands a local directory to a slot for development.
- Delivery of packs from the platform (desired state, prefetch, pin at dispatch) follows.
