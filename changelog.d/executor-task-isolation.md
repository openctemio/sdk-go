### Security: a task can no longer read another task's files

- The process sandbox hid only the sensor's protected paths, so a task could read and list the directories of the tasks running beside it (on a shared sensor, another tenant's checkout and tool output). The task root (`executor.TaskRoot()` and the backend's `WorkRoot`) is now hidden from every task; a task reads and writes only its own directory and the paths it is given.
- The tool host's protocol directory moved from `$TMPDIR/openctem-tool-*` to the task root (`executor.NewTaskDir`).
- A task root must be a directory owned by the sensor's user: a symbolic link or another user's directory is refused, and an owned one is closed to other users (0700).
