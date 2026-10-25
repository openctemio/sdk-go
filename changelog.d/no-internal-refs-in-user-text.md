### Changed: sensor warnings and descriptions no longer cite internal design documents

- The "no local policy" warning is now one sentence with its fix: this sensor was paired before local policies were required, so it accepts any target outside the built-in deny list; install the policy file or set `SENSOR_REQUIRE_LOCAL_POLICY=true`. The second, near-duplicate warning is folded into it.
- The `SENSOR_API_KEY` description, the manifest conformance skip message and the tool schema descriptions no longer cite RFC numbers.
- A test (`internal/refgate`) fails when a Go string or shipped schema cites an RFC number, research note or decision id.
