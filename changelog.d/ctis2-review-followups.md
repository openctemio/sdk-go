### Security: the tool runtime and the test receiver tighten two CTIS 2.0 checks

- A tool run without a valid capability can no longer pass off its own `extensions["io.openctem"]` metadata as the runtime's stamp: `toolrt.Stamp` clears that namespace (with a valid capability, the runtime's capability still replaces the tool's).
- The conformance fake receiver refuses a document whose `metadata.id` equals the delivery (report) id, and checks the command binding before it answers a retry, so the same document sent for another command is a binding mismatch, not an answer about that command's report.

### Fixed: an order-dependent sensor kit test

- `TestRun_ConfigReport_ChecksAndNoSecretOnTheWire` set the removed `AGENT_NAME`, which a sensor refuses at start; it passed only when another test had run the once-per-process check first. The test no longer sets it (refusal is covered by `TestMigrateLegacyEnv_RefusesRemovedNames`).
