### Added: the runtime maps a capability task onto the tool

- `tool.Task` gains three fields:
  - `Capability` (`scan.ports@1`);
  - `Params`: the capability's standard params, as the workflow set them;
  - `MaxTier`: the job's tier ceiling.
- `Manifest.ApplyParams` maps the params onto the tool's config keys through `implements[].params`, and consumes them. The tool reads only its config.
- `toolhost` applies the contract before a task starts:
  - the job's tier ceiling;
  - the param mapping;
  - the rate cap.
- After the task, `toolhost` checks the capability's required output with `capability.Check` and the tool's output shape.
  - Violations are logged and counted in `Stats.ContractViolations`, and an ok task becomes `partial`.
  - Records are still delivered, and the platform checks them again.
- Provenance carries `capability` and `contract_violations`. The run message carries `capability` and `max_tier`; adapters may ignore them.
- `toolhost.RatePolicy`: a policy with `CapRate` caps the tool's `safety.rate_param` key, and sets it when the task left it unset. The change is logged. The sensorkit policy caps it by the local policy's `rate.max_rps`.

### Security

- Each of these is `invalid_input` before anything starts:
  - a standard param the tool does not map;
  - a value outside the capability's enum or the tool's narrowed values;
  - an integer outside either bound;
  - a malformed port list;
  - a config key that the task also sets to another value;
  - params without a capability;
  - a capability the tool does not implement.

  Nothing is dropped silently.
- A tool's minimum tier is the highest of its declared tier, the capability floors, and T2 for any side effect. When it is above the job's `max_tier`, the task is `refused_by_policy` before it starts.
- The local policy's rate cap applies whatever the workflow asked.
