# Per-host budget

Every scan job runs under a **per-host budget**: the most requests per second and the most requests in
flight that one target host gets from the job. It holds whatever tool runs, however many of the job's
targets name the same host, and whatever the job's other rate settings say.

A host is the politeness host of a target (`adapt.HostKey`, contract `politeness.HostOf`): the name or
address without scheme, port or path. `http://a.example.com/x`, `https://a.example.com:8443/` and
`a.example.com:22` share one budget.

## Levels

| level | requests/s per host | in flight per host | use |
|---|---|---|---|
| `gentle` | 5 | 2 | fragile or production applications |
| `standard` (default) | 20 | 8 | everything, unless something says otherwise |
| `fast` | 100 | 25 | a lab or staging host |

The levels are `adapt.PacingGentle`, `adapt.PacingStandard` and `adapt.PacingFast`. A level also sets the
request timeout, the retries, a tool's own host error budget, the rate of a sweep over many hosts and the
packets per second of a port scan (`adapt.Pacing`).

## Where a job's budget comes from

`adapt.ResolveBudget` (called by `core.DefaultCommandExecutor.HostBudget`), in this order:

1. **The sensor's level.** Standard, unless the sensor's own operator set `SENSOR_PACING_LEVEL`
   (`sensorkit.Options.PacingLevel`) to `gentle` or `fast` (an unknown value is reported at start and the
   sensor runs at `gentle`). A sensor that talks to a platform which sends
   no budget runs every job at this level.
2. **The job's signed budget**, when the job carries one: the `pacing` member of the signed job statement
   (`jobsig.Statement.Pacing`), `{"level": "gentle"}` or explicit numbers
   `{"level": "custom", "target_rps": 10, "target_inflight": 4}`. It replaces the sensor's level, lower or
   higher. Only the signed statement can set it: no unsigned command field, payload key or settings layer
   does.
3. **The operator's ceiling**, which always wins: the local policy's `rate.max_host_rps` and
   `rate.max_host_inflight`. Without them the built-in hard ceiling applies: 200 requests/s and 50 in
   flight per host (`adapt.HardBudgetCeiling`). A budget above the ceiling is lowered to it and the result
   lists what was lowered (`HostBudget.Clamped`). A job is never refused for asking too much.

A statement whose `pacing` member is malformed (an unknown level, a negative number) is refused when it is
verified (`jobsig.ReasonPacing`): a job signed to run gently never runs at the sensor's default instead.

## Who enforces it

**A task whose network is confined** (the default: tools run in the sandbox and reach the network only
through the task's forwarder, `pkg/sensorkit/egress`):

- the forwarder paces every connection to a host, and every request on a connection it reads, under the
  budget's rate (`adapt.HostRate`: slow start at a quarter of the rate, a tenth more per clean window,
  halved on push-back);
- it holds at most the budget's in-flight number of connections to a host open; a connection over it
  waits for one to end;
- the bound does not depend on the tool: a tool whose flags ask for more waits at the forwarder.

The tool's own flags are derived from the same budget so that it does not queue behind the forwarder
(`HostBudget.ToolPace`, `HostBudget.SweepPace`): a tool whose rate flag is global to its process (nuclei
`-rate-limit`) gets the budget times the hosts it works at once (at most 8 at Standard), a tool with a
rate key in its manifest (`safety.rate_param`) has that key lowered to it by the tool host.

**A task whose network is not confined** (`SENSOR_SANDBOX=off`, or a tool run in process): nothing is in
the path, so the derived flags are the enforcement. A rate flag that is global to the process cannot be
split per host, so the whole run then gets **one host's budget**: no host can receive more, whatever the
tool does with its list. Runs over several hosts are slower in this mode.

Call `toolhost.RunOptions{HostBudget: &budget}` for a tool that speaks HTTP to its targets. A port scan is
paced in packets per second (`Pacing.ProbePPS`) and is not under this budget.

## Back-off

`adapt.HostRate` reacts to what a host answers:

| signal | effect |
|---|---|
| 429, 503, a vendor's rate-limit page | the host's rate is halved (at most once per window); a `Retry-After` is waited out (capped at 5 minutes; connections are refused instead of held when it is longer than 10 seconds) |
| five such answers in a row with no ordinary HTTP answer between them (counted at most once a second) | the host's breaker opens for 15 s (then 30 s; at least as long as `Retry-After` asked); the host is a coverage gap `throttled` whose detail holds only counts: `throttled by target: 429=12 503=1 retry_after=30s backoffs=5 circuit_opens=1` |
| a vendor's challenge or block page | the host is a gap `blocked` from the first answer |
| a timeout or a failed connection | the rate is halved; five in a row open the breaker |
| a clean window after a back-off | a tenth of the budget is added back; a breaker that opened is closed by the first request that is answered after its open time |
| three breaker openings in one task | the host is given up for the task |

A run that met push-back completes **partial**: the hosts are listed as coverage gaps and everything the
tool delivered is kept. Nothing is dropped because a host throttled.

### HTTPS without interception: the canary

The forwarder reads the answers on plain HTTP, and on connections it terminates anyway (a web scope, path
limits, an identification it injects). Ordinary HTTPS is passed through unread: terminating TLS for every
run would break every check that inspects the certificate and would put the plaintext of every scan in
the forwarder. On such connections the forwarder sees dials and resets only.

`adapt.Canary` closes that gap. While a task runs, the tool host sends one plain `GET /` to each origin a
target names by an `http` or `https` URL, every 10 seconds (every 3 seconds after a push-back), through the
same forwarder, scope check, proxy pool and identification as the tool's requests. The request respects
the host's breaker and `Retry-After`, takes a token of the host's rate when one is free and never waits
behind the tool's requests (so it adds at most one request every 3 seconds to the host's rate, and holds
none of the host's connection slots). It follows no redirect, is never retried, and its answer feeds the
host's rate controller: a 429 or 503 there halves the rate of the tool's connections, a run of them opens
the breaker.

In an unconfined run the canary feeds a controller of its own. It cannot slow a tool it is not in the path
of; when **every** host of the task has its breaker open, the tool host stops the tool (a protocol cancel,
then a kill), keeps what the tool delivered, lists the rest of the targets as unfinished and ends the run
partial with the error class `rate_limited`.

What the canary covers, and what it does not:

| covered | not covered |
|---|---|
| a host that rate-limits or blocks the scanner's address as a whole (the usual WAF and rate-limiter behaviour): 429, 503, `Retry-After`, vendor block, challenge and rate-limit pages, resets and timeouts of a request the host served before | a limit that applies only to the paths, payloads or session of the tool's own requests |
| HTTPS and plain HTTP, confined and unconfined runs, a job's proxy pool | a host no target names by an `http(s)` URL (a bare host name or `host:port`): the scheme and port are not known, and a canary never contacts an origin the job did not name |
| up to 64 hosts per task | further hosts of the task (they still run under the budget) |
| a 403 from an origin that answered the same request before (a block after five in a row) | an origin whose root is forbidden from the first request on (read as an ordinary answer) |
| unconfined: stopping the tool when all of its hosts are open | unconfined: slowing one host of a run over several (the gap is recorded; the tool goes on) |
| | a tool described only by a manifest (the exec profile) is held by the forwarder and has its rate key lowered, but gets no canary |
| | a host whose certificate does not verify (self-signed, expired, another name): the canary verifies certificates and reads nothing from such a host, so what an unauthenticated peer answers never steers the rate |
| | latency growth as a congestion signal (not implemented) |

## What the result says

`metadata.target_rate` of a job result (`adapt.Summary`) carries, besides the rates:

```json
{
  "budget": {"level": "standard", "rps": 20, "inflight": 8, "source": "sensor",
             "clamped": [{"key": "rps", "asked": 100, "to": 30, "by": "sensor_ceiling"}]},
  "backoffs": 4, "circuit_opens": 1,
  "host_stats": [{"host": "a.example.com", "rate": 2.5, "min": 1, "backoffs": 4, "circuit_opens": 1,
                  "http_429": 12, "http_503": 1, "retry_after_seconds": 30}],
  "canary": {"hosts": 1, "probes": 14, "pushback": 6, "held": 3}
}
```

`host_stats` lists the hosts that were slowed or opened (at most 100). The members are additive: a
receiver that does not know them ignores them. The task's log has one line with the budget and the counts,
one per value the ceiling lowered and one per host that pushed back. Host names appear there as they do in
the existing rate-change lines; nothing a host sent is logged.

`toolhost.Pacing()` returns the process totals (tasks under a budget, back-offs, breaker openings,
throttled hosts, tools stopped, values clamped) and `toolhost.NewPacingCollector()` exposes them as
Prometheus counters `openctem_sensor_pacing_*`, without labels.

## Version skew

- **A new sensor with an older platform.** The platform signs no `pacing` member: every job runs at the
  sensor's level, Standard. Nothing the platform has to change.
- **A new platform with an older sensor.** An older sensor refuses a signed statement with a member it
  does not know. A platform therefore adds `pacing` only for a sensor that reports the capability
  `pacing.budget@1` (`core.CapabilityHostBudget`); an older sensor gets the statement without it and runs
  at its own defaults.
- The local policy keys `rate.max_host_rps` and `rate.max_host_inflight` are additive keys of policy
  schema v1. A sensor from before them refuses a policy file that names them (an unknown key), as it does
  for any key it does not know.

## Security notes

- A job cannot raise its budget above the sensor's ceiling: the ceiling is applied last, and the built-in
  hard ceiling bounds the operator's own.
- Only the verified signed statement sets a budget. The command's unsigned fields, the payload, the
  settings layers and a tool's config can only lower what a tool sends (a lower rate stays lower); they
  cannot raise the budget.
- Back-off cannot be turned off, by a job or by the operator.
- The canary sends a fixed request (`GET /`, no body, the job's identification). Nothing in a job chooses
  its method, path, headers or destination beyond the origins of the job's own admitted targets, and it
  dials only what the task's scope admits.
- Nothing rotates addresses or changes the identification to get past a block. The only reactions are to
  slow down, to stop, and to report.
