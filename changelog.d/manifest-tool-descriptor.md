### Added: the sensor manifest carries each tool's full descriptor; scan jobs carry their capability

- `core.ToolContract` gains two fields:
  - `Descriptor`: the tool's full manifest in canonical JSON. Its SHA-256 is `Digest`, and it is left out above 64 KiB.
  - `Origin`: `builtin` for a tool compiled into the sensor, `adapter` for one the operator installed.

  Both travel in the sensor manifest, which is registered only when it changes. Heartbeats carry only the manifest digest, so their size is unchanged.
- A tool on the contract reports the capability ids it implements (`scan.ports`) as its capabilities, beside its older capability words.
- `ScanCommandPayload` gains `capability` (`scan.ports@1`), `params` (the standard params) and `max_tier`, and `ScanOptions` carries them.
- A `core.CapabilityScanner` (`TakesCapabilityJobs`) receives these job fields. A `toolcompat` scanner whose manifest implements a capability is one, and it hands them to the tool runtime, which maps the params and checks the tier.

### Security

- A capability job sent to a scanner that cannot apply it fails. This covers a job carrying a capability, params or a tier ceiling. Its settings are never dropped silently.
- The executor refuses:
  - malformed capability references, including a ref without its major and look-alike case;
  - params without a capability;
  - an unknown tier;
  - more than 64 params, or a param over 16 KiB.
- The platform derives a tool's trust level from `origin`, which the sensor sets from how the tool was loaded, never from the tool's own claim.
