### Added: a browser sandbox for tools that run a web browser

- A tool manifest may declare `permissions.sandbox: browser` (with `network: targets`). Its task runs only on a sandbox
  that enforces every control in required mode and confines the network; otherwise the tool host refuses it (never
  unconfined). The tool runs as a non-root user (1000) of its own user namespace beneath the confined one, so it holds
  no capability over the task's network namespace; it may create user, PID and network namespaces (what Chromium's
  renderer sandbox makes) and no mount, UTS, IPC, cgroup or time namespace, never `setns`; and it may write `/proc`
  (the browser writes its sandboxed children's id maps). Every other control is unchanged.
- `executor.TaskSpec.Browser` and `executor.ErrBrowserNeedsConfinement` (Prepare refuses a browser task on an
  unconfined backend or with the sandbox off).
