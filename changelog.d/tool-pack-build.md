### Added: `openctem tool build` makes the pack image; CI templates publish and sign it

- `openctem tool build <pack> (--output <oci-dir> | --push <repo[:tag]>)` builds a multi-platform OCI image of a tool pack without a container daemon: the base image pinned by digest plus one reproducible layer holding the pack at `/opt/openctem/pack`, per-architecture files from `.build/<os>-<arch>/`, no entrypoint, user 65532, no timestamps, and the labels `io.openctem.pack.{name,version,publisher,tier,digest}`. The same pack and base give the same digest; the command prints it.
- Symbolic links and special files are never packed (the build fails), nor are `.git`, `.build` and `__pycache__`; a pack that does not validate is not built.
- The GitHub and GitLab CI templates gain a publish job: on a tag equal to the pack version, build, push and sign the image digest keylessly with cosign.
