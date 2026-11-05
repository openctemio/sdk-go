### Security: out-of-band callbacks use only the sensor's own interaction server, through the forwarder

- New `egress.OOBServer` (`Scope.OOB`, `toolhost.RunOptions.OOB`): a confined task's forwarder carries the interaction API (`POST /register`, `GET /poll`, `POST /deregister`, body at most 64 KiB) of the one server the sensor's operator configured, adds its token itself (the tool's `Authorization` and `Cookie` are dropped), and dials it with verified TLS at public addresses only unless the operator allowed a private server. Any other request toward that host, and any public interaction server, is refused. The job's web scope and path limits do not apply to it, and it is not counted as a target.
- Measured with the real nuclei v3.11.1 (built with interactsh v1.4.1) behind the forwarder in a web-scoped task: `-iserver http://<server> -pi` registers, polls and deregisters through the forwarder with the forwarder's token only, the callback payloads name the server's zone, and nothing else is proxied.
- The extra-args guard now refuses nuclei's long names `-interactsh-server` and `-interactsh-token` (only `-iserver` and `-itoken` were refused, so an extra arg could point callbacks at any server) and the callback timing flags the sensor sets.

### Behaviour change: a local policy without allow_interactsh follows the platform, and a refusal of callbacks narrows the job

- `allow_interactsh` absent from a local policy now follows the platform's job; only `allow_interactsh: false` turns callbacks off. A job that asks for callbacks on a sensor whose policy turns them off (or that requires a policy and has none) is no longer refused: it runs without them (`ScanOptions.OOBOffReason`), and its result metadata `oob` says why.
- New `core.OOBState`, `ScanResult.OOB` and result metadata key `oob` (`core.MetaOOB`): what a scan did with the callbacks its job asked for (`on`, or `unavailable` with a reason).
