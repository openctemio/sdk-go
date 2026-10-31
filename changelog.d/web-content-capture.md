### Added: web content captures on a live host

- `core.LiveHost.WebContent` (`core.WebCapture`) carries the result of a web content fetch (capability `monitor.web_content`): URL, final URL, status, content type, size, SHA-256 and a capped text body. It is passed through to `ctis.LiveHostInput.WebContent`, which bounds it again. Absent unless a probe fills it, so existing reports do not change.
- Re-pinned `github.com/openctemio/ctis` for `monitor.web_content@1` and `WebCaptureInput`; the `pkg/ctis` aliases are regenerated.
