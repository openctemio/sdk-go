### Added: the `openctem` CLI on Windows

- Releases ship `openctem_<version>_windows_amd64.zip` and `openctem_<version>_windows_arm64.zip` (each with `openctem.exe`), listed in `SHA256SUMS` and covered by its keyless cosign signature like the Linux and macOS archives.
- `openctem import` expands file patterns itself (`openctem import C:\scans\*.nessus` works in cmd.exe and PowerShell, which do not expand them) and sends more than 10 files 10 at a time, each upload with its own receipt; the exit status is the worst of them.
- `openctem import` reads exports written by Windows tools: UTF-16 with or without a byte order mark (XML declarations saying UTF-16 included), a UTF-8 byte order mark and CRLF line ends.
- `--ca-file` / `OPENCTEM_CA_FILE` (import, targets export, run) add a private CA to the system trust store (on Windows the certificate store); verification is never skipped. `HTTPS_PROXY` is honoured as before.
- `--out` and the private temporary files of `openctem run` get, on Windows, a DACL for the current user and SYSTEM only (the equivalent of mode 0600).
- `openctem run` drops `OPENCTEM_API_KEY` from the command's environment whatever case the name is written in (Windows names are case-blind).
- CI builds every target for real (the build matrix set no GOOS before) and runs the CLI's tests, a cmd.exe exit-status check and `go install github.com/openctemio/sdk-go/cmd/openctem@<commit>` on `windows-latest`.
- Docs: a PowerShell install that checks the zip against `SHA256SUMS` (optionally the cosign signature), unblocks it and adds it to the user's Path; why an unsigned `openctem.exe` triggers SmartScreen and how `go install` avoids it; AppLocker/WDAC hosts.
