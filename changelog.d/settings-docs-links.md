### Fixed: settings docs links point at the settings reference

- `settings.DocsBase` (and so each setting's default `DocsURL()`, and the
  links in `docs/SETTINGS.md`) is `https://docs.openctem.io/sensors/settings/`
  with an anchor per setting. The old `/sensor/settings` page did not exist.
- CI checks every docs.openctem.io and GitHub file link in the repository
  (`scripts/check_docs_links.py`, job "Docs links").
