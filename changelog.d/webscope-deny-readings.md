### Security: web scope deny paths hold when escaped, with `*` segments and for lenient server spellings

- A deny path stored with a percent-escape (`/files/My%20Docs`) never matched, because requests are compared decoded: `/files/My%20Docs/a.bak` was allowed. A deny path now holds as written and decoded.
- A `*` segment of a deny path (`/tenants/*/admin`) was compared literally. It now matches any one segment, as the platform's path exclusions read it.
- Requests are checked in every reading a lenient server may act on: case folded to ASCII (`%C5%BF` is `s`), trailing dots and spaces of a segment dropped (`/admin./x`), and decoded twice (`/%252e%252e/admin`).
- `Scope.Validate` adds the decoded form of each escaped deny path, so a tool that maps the deny list onto its own flags gets both forms. `webscope` now uses `github.com/openctemio/contract/webpath` (v1.3.1), the reading the platform uses.
- These hold on the egress forwarder (confined tasks) and in `tool.Context.HTTP`. Operators: upgrade the sensor.
