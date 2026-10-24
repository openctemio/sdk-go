### Security: a tool directory is owner-checked file by file

- The sensor checked the adapter directory, the tool directory, `tool.yaml` and the program only; a helper module next to the program (for example `openctem_tool.py`), a mapping or a wordlist could be group/world-writable or owned by another user and be swapped by a local user.
- Every file and directory of a tool's directory (to 4 levels and 1024 entries) must now be owned by root or the sensor's user, not group/world-writable and not a symbolic link. For a manifest placed directly in the adapter directory, the program and the output mapping it references are checked.
- Operators: a tool directory with such a file is now refused and the `adapter_refused` check names the file; fix the permissions (`chmod go-w`, `chown`) and keep only what the tool needs in the directory.

### Added: `sensorkit.InspectAdapterDirs`

- `InspectAdapterDirs(dirs, builtin)` reports the tools the sensor would load from `SENSOR_ADAPTER_DIRS` (name, version, manifest path, digest, capabilities, class, tier, network) and the manifests it refuses with the reason, without a platform. The kit loads from the same function, so the two cannot disagree.
