### Documentation: a quickstart for writing a tool, with a runnable example

- `docs/tool-quickstart.md` walks a third-party author from install to a tenant approving the tool: manifest, the two-method contract and builder, local runs, the conformance harness and `FakePlatform`, results, egress and scope, packaging and compatibility.
- `examples/hello-tool` is the tool the page builds. Its test runs it in-process, through `conformance.RunToolSuite` on the built program, and into a `FakePlatform`, so the quickstart cannot drift from the SDK.
