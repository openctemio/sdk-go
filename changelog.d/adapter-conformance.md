### Added: a conformance kit for tools in any language

- `conformance.RunToolSuite(t, "tool.yaml", opts)` and the command `openctem-conformance tool <tool.yaml>` check a tool that is its own program (any language) against adapter protocol v1 the way a sensor runs it: the manifest loads and validates; the handshake answers protocol 1, ignores an unknown message and describes the tool exactly as its tool.yaml does; an unknown configuration key is refused; standard output carries only protocol messages; the program exits 0 when its input ends; a cancel is honoured within the grace; and each self-test fixture runs through the runtime's own host (with every runtime check) and produces exactly the expected normalized CTIS. `-update` (or `OPENCTEM_UPDATE_GOLDEN=1`) writes the expected reports.

### Documentation

- `docs/adapter-protocol.md`: the language-neutral contract for a tool in any language (transport, conversation, the rules the runtime enforces, time and cancel, exit codes, conformance, installing).
- `examples/python-adapter`: a complete tool in plain Python (standard library only) with its tool.yaml and self-test fixture, checked in CI by the conformance suite.
