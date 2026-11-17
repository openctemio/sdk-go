# Per-host budget

A scan job's tools that send requests to its targets run under a **per-host budget**: the most requests
per second and the most requests in flight that one target host gets from the job, however many of the
job's targets name the same host. This page says where the budget comes from, what enforces it on each
path, and what it does not hold.

A host is the politeness host of a target in canonical form (`adapt.HostKey`): the name or address without
scheme, port or path. `http://a.example.com/x`, `https://a.example.com:8443/` and `a.example.com:22` share
one budget, and so do the spellings of one host (below).

## Levels

| level | requests/s per host | in flight per host | use |
|---|---|---|---|
| `gentle` | 5 | 2 | fragile or production applications |
| `standard` (default) | 20 | 8 | everything, unless something says otherwise |
| `fast` | 100 | 25 | a lab or staging host the sensor's operator owns |

The levels are `adapt.PacingGentle`, `adapt.PacingStandard` and `adapt.PacingFast`. A level also sets the
request timeout, the retries, a tool's own host error budget, the rate of a sweep over many hosts and the
packets per second of a port scan (`adapt.Pacing`).

## Where a job's budget comes from: the lowest limit wins

`adapt.ResolveBudget` (called by `core.DefaultCommandExecutor.HostBudget`) takes, **for each of the two
numbers on its own, the lowest** of:

1. **The sensor's level.** Standard, unless the sensor's own operator set `SENSOR_PACING_LEVEL`
   (`sensorkit.Options.PacingLevel`) to `gentle` or `fast`. An unknown value is reported at start and the
   sensor runs at `gentle`.
2. **The job's signed budget**, when the job carries one: the `pacing` member of the signed job statement
   (`jobsig.Statement.Pacing`), `{"level": "gentle"}` or explicit numbers
   `{"level": "custom", "target_rps": 10, "target_inflight": 4}`. Only the signed statement carries it: no
   unsigned command field, payload key or settings layer does.
3. **The operator's ceiling**: the local policy's `rate.max_host_rps` and `rate.max_host_inflight`.
4. **The built-in hard ceiling**: 200 requests/s and 50 in flight per host (`adapt.HardCeilingRPS`,
   `adapt.HardCeilingInflight`; constants).

So **a job can only lower** what a host gets. A signed Fast on a Standard sensor runs Standard; a signed
Gentle on a Fast sensor runs Gentle; a ceiling below the level wins. The one who can raise it is the
sensor's own operator, by setting the sensor's level (within the ceilings) when the hosts are the
operator's own. A job is never refused for asking for more: it runs at the lower limit and the result says
so.

The result names the limit that set each number (`budget.won_by`: `sensor_level`, `job`,
`operator_ceiling` or `hard_ceiling`; on a tie the first of them in that order) and lists every value that
was asked for and did not apply (`budget.clamped`).

A statement whose `pacing` member is malformed (an unknown level, a negative number) is refused when it is
verified (`jobsig.ReasonPacing`): a job signed to run gently never runs at the sensor's level instead.
Should such a budget reach `ResolveBudget` all the same, it reads as Gentle.

## One host, one key

`adapt.HostKey` (for a target) and `adapt.CanonicalHost` (for a host) are the one key function. The task
forwarder, the canary, the mapping of a budget to a tool's flags and the coverage gaps all use it, so no
spelling of a host gets a budget of its own:

- an IPv6 address in any form, an IPv4-mapped IPv6 address (`::ffff:192.0.2.1`), brackets and a zone;
- an IPv4 address in a form the C library reads as one: hexadecimal, octal or decimal parts, fewer than
  four parts (`0xc0000201`, `3221225985`, `0300.0.2.1`, `192.0.513`), also when it is written with
  full-width digits, letters or dots, which a resolver maps to their ASCII forms first (`0x7f．0．0．1`);
- a name in upper case, with a trailing dot, in Unicode or in its ASCII form (`bücher.example` and
  `xn--bcher-kva.example`).

**Names of one address.** A key function cannot know that two different names are one server. The task
forwarder can: it dials the addresses pinned at admission. Every connection is counted under its host
**and** under the address it is dialed at, and what the forwarder reads on a connection is reported to
both. N names of one address therefore share that address's **rate and connection slots** besides their
own, so one server with many names gets one budget.

**An address only slows.** One address often serves many unrelated sites (a CDN edge, shared hosting, an
ingress), and what one of them answers says nothing about the others. So the address has a rate and slots
and nothing else:

- push-back, a vendor's block or challenge page, a `Retry-After` and failed connections reported for an
  address **lower that address's rate** (halved at most once per window, never below the floor of one
  request a second, raised again on clean windows) and do nothing more;
- an address has **no breaker, no `Retry-After` hold and no cooldown**, in the task and in the sensor-wide
  state: nothing a name was answered refuses or holds a connection of another name of its address, in the
  same task or in the tenant's next one;
- breakers, block cooldowns and `Retry-After` holds exist **per host name** only. A name that is blocked
  or asked to wait is backed off itself, and is the coverage gap;
- this also holds when a target names the address itself: that target is a host with its own breaker,
  and the names reached at the address take only its rate.

The cost of sharing the rate is that one name's push-back slows the other names of its address for a
while. That is the limit of what one name can do to another: slower, never stopped. Quantified: an
address's rate is halved at most once per two-second window down to the floor of one request a second,
and raised by a tenth of its ceiling per clean window, so from the floor back to Standard (20 a second)
takes about 20 seconds of clean windows. A name that keeps pushing back, for example one 429 per window
between ordinary answers, keeps its address at the floor for as long as it does so, for every name of
that address; the sensor-wide entry of the address is then at the floor too (shared between the
organizations that scan there). Its own breaker need not open.

In a result, `host_stats` entries with `"address": true` are such addresses (`circuit_opens` is always 0
there); coverage gaps are reported on names. Without a forwarder nothing knows the address; see the
unconfined case below.

## What is enforced where

### A task whose network is confined

The default: tools run in the sandbox and reach the network only through the task's forwarder
(`pkg/sensorkit/egress`).

| traffic | what the forwarder holds |
|---|---|
| a new connection to a host (any protocol) | one token of the host's rate and of its address's rate (`adapt.HostRate`: slow start at a quarter of the rate, a tenth more per clean window, halved on push-back), and one of the host's and of the address's connection slots (the budget's in-flight number) for as long as it is open; a connection over the slots closes an idle one and takes its slot, or waits for one and is refused after 15 seconds (below) |
| plain HTTP, and HTTPS the forwarder terminates anyway (a web scope, path limits, an identification it adds) | every request waits for the rate; every answer is read (429, 503, `Retry-After`, block pages) |
| HTTPS passed through (the ordinary case), HTTP/1.1 | the tunnel's first request is covered by the connection's token; **every further request on a kept-alive tunnel waits for the rate too** (below). Requests in flight are within the connection slots, since HTTP/1.1 carries one request at a time per connection |
| HTTPS passed through, HTTP/2 | the rate is held for a client that writes each request in a TLS record of its own (Go's HTTP/2 client, which the scan tools are built on): every record of a client that offers HTTP/2 waits for the rate. **Not held:** the requests of a client that packs several into one record (bytes only), and the streams in flight (one connection carries many). There the tool's own flags are the enforcement (below) |
| HTTPS passed through, HTTP/1.1 pipelining without an HTTP/2 offer | **not held as requests**: bytes and connections only |
| a tunnel that is not TLS | counted like HTTP/1.1: client data after the host spoke is a request |

**Connection slots** (`egress/hostbudget.go`). A slot counts an open connection: the connections open to
a host, and to an address, never exceed the budget's in-flight number, and so neither do the requests in
flight over HTTP/1.1.

- a kept-alive connection keeps its slots while it is open, and is **idle** between requests. On a
  connection the forwarder reads this is exact (between an answer and the next request). On a tunnel it
  passes through, the tunnel is idle when the host sent the last bytes and nothing has moved for one
  second (`Limits.SlotIdle`); a tunnel that waits for an answer is never idle, however long the host
  takes;
- a new connection that finds every slot taken **closes the oldest idle connection** of that host (or
  address) and takes its slot, at once or as soon as one goes idle while it waits. Idle kept-alive
  connections of one name therefore never keep the other names of its address, or the name's own next
  connection, waiting. The tool sees its idle connection closed, as when a server closes an idle
  kept-alive connection, and opens a new one for its next request; nothing is reported about the host;
- on a tunnel's first request, and on a tunnel whose client offered HTTP/2, the host's last bytes need
  not be the answer (a TLS 1.3 session ticket arrives after the handshake; HTTP/2 control frames arrive
  between answers), so such a tunnel is given five seconds before it counts as idle. **Limit:** an answer
  to such a request that pauses longer than five seconds after other bytes from the host counts as idle
  while it is still in flight, and a connection that waits for its slot may then close it (the tool
  sees that answer cut short). Because the forwarder cannot tell such a cut from a tunnel that was
  only idle, closing a tunnel in that state makes its host a coverage gap `slots_full` (below), so a
  cut answer is never read as a host fully scanned;
- a connection that finds no slot for 15 seconds (`Limits.DialTimeout`), every slot being held by a
  connection with a request in flight, is refused, and **its host is a coverage gap** `slots_full` (detail
  "a connection was refused: every connection slot of the host's budget stayed in use"): the request
  never left, so the result must not read as "nothing found" for that host. The sensor's own bound
  caused it, not the host: the target keeps the outcome the tool gave it, and the gap alone makes the
  host not covered and the run partial (no follow-up command scans the host again at once; the next run
  does). The gap is never reported as the host pushing back, and it is not a reason to hold the host's
  findings.
  It is the weakest gap reason: anything the host did itself (`rate_floor`, `blocked`, ...) replaces it.

**Requests on a tunnel the forwarder does not read** (`egress/tunnel.go`). The forwarder does not
terminate TLS for ordinary HTTPS: that would break every check that inspects the certificate and put the
plaintext of every scan in the forwarder. It reads the five plaintext bytes of each TLS record header the
client sends (type and length; nothing is decrypted). An application-data record that follows bytes from
the host starts a new request, because HTTP/1.1 sends a request only after the answer to the one before.
Each such request waits for a token of the host's rate and of the address's rate before its first byte is
passed on. In addition:

- a client whose ClientHello offers HTTP/2 (the hello is plaintext) may send requests without the host
  speaking between them. On such a tunnel **every** application-data record of the client waits for a
  token, one for each 4 KiB of it. A client that writes each request in a record of its own is then
  counted once per request or more (a window update or a request body is a record too). A window update
  cannot be told from a request by the size of its record (a request whose header fields are all in the
  connection's compression table is as short), so window updates are charged: a long HTTP/2 download
  takes more tokens than its one request, and past the tunnel's lifetime its next window update ends
  the tunnel;
- a token covers at most 4 KiB of client data (one TLS record of up to 16 KiB counts as one where the
  client offers no HTTP/2): more client data without the host speaking takes another token;
- a tunnel older than 2 minutes carries no further request: it is closed where the next one would start,
  before a byte of it is passed on, so the client opens a new connection, takes a token for it and repeats the
  request. A client repeats a request that is safe to repeat by itself; one that is not (a POST) fails
  once on such a tunnel and is left to the tool's own retry;
- a request the host's breaker refuses closes the tunnel the same way: an open breaker stops kept-alive
  tunnels, not only new connections.

What this **guarantees**:

- over HTTP/1.1 on HTTPS, with connections kept alive or not, the requests a host receives per second are
  within the budget's rate, exactly as on plain HTTP, and the requests in flight are within the budget's
  connections;
- over HTTP/2 from a client that writes each request in a TLS record of its own, the requests a host
  receives per second are within the budget's rate (measured with Go's client: 32 streams as fast as they
  can stayed within the rate, for a target that answers in 2 ms and for one that answers in 300 ms; such a
  client is counted more than once per request, for its window updates and settings, so it runs below
  the rate);
- for any protocol, the client bytes a host receives per second on tunnels are at most the rate times
  16 KiB (4 KiB where the client offers HTTP/2).

What it does **not** guarantee:

- the number of requests of a client that packs several into one TLS record: an HTTP/2 client that
  batches its frames (a browser that starts many requests at once), or HTTP/1.1 pipelining from a client
  that does not offer HTTP/2. The forwarder cannot tell such requests apart without reading them: only
  the byte bound and the tunnel lifetime hold;
- the **requests in flight** over HTTP/2: the connection slots bound connections, and one HTTP/2
  connection carries many streams.

For those, **the tool's own rate and concurrency flags are the enforcement**. An upload larger than 4 KiB
takes more than one token: it is slower, never faster. A TLS 1.3 handshake the server restarts
(HelloRetryRequest) costs that tunnel one token more. A long-lived stream on a tunnel (a websocket) ends
with the tunnel's lifetime: the tunnel is closed at the client's next message after two minutes.

**The tools' flags.** Each tool's flags are derived from the same budget (`HostBudget.ToolPace`,
`HostBudget.SweepPace`), for two reasons: a tool should not queue behind the forwarder, and the flags are
the enforcement where the forwarder cannot count. A tool whose rate flag is global to its process (nuclei
`-rate-limit`) gets the budget times the hosts it works at once (at most 8 at Standard); a tool with a
rate key in its manifest (`safety.rate_param`) has that key lowered to it by the tool host. A rate or
concurrency a person set above the budget is lowered and recorded in the result (`budget.clamped`, with
what was asked and what applies) and in the run's log.

### A task whose network is not confined

`SENSOR_SANDBOX=off`, or a tool run in the sensor's own process. Nothing is in the path:

- the derived flags are the **only** enforcement. A rate flag that is global to the process cannot be
  split per host, and a list cannot be read for the addresses its names share, so the whole run gets
  **one host's budget**, whatever its list: no host and no address can receive more. Runs over several
  hosts are slower in this mode;
- nothing reads what a host answers: there is no back-off, no breaker and **no canary**;
- the result says so: `metadata.target_rate.pacing_limited` is `no_forwarder`, the run's log has a
  "pacing limited" line and `openctem_sensor_pacing_limited_tasks_total` counts such tasks.

### Which tools

**Every tool whose manifest says it can connect to its targets**: `permissions.network: targets`;
`egress-proxy`, which reaches any public host and so its targets too (its forwarder holds every host it
admits to the budget, with the same slots, rate and canary); and a `vendor` tool whose vendor hosts, as
read from the task's configuration, name one of the task's targets (a host a target names, or an address
in a target's range), so a configuration cannot name a target as a vendor host to reach it outside the
budget.
**Limit:** the vendor hosts are compared with the targets by name, literal address and range, not by
what they resolve to: a vendor host that is a DNS alias of a target (another name for the target's
address) is not caught, and the vendor tool reaches that address without the per-host limits. Only a
configuration of the scan's own settings can name it.

The tool host refuses to start such a tool without a valid budget (`toolhost.ErrNoHostBudget`, a refusal before
any process starts), whatever started it: a tool compiled into the sensor, an adapter the operator
installed in an adapter directory, a tool given to `Kit.AddTool`, a retest. A caller cannot forget it.

**Cost for `egress-proxy` tools that send nothing to their targets.** Tools that fetch from public
services (vulnerability databases and image registries, rule and pack hosts, RDAP and ASN services) and
never connect to their targets declare `egress-proxy`. Their forwarder cannot tell such a host from a
target, so every host they reach gets the per-host budget: on Gentle 5 requests per second and **two
open connections per host and per address**. A transfer that holds a connection longer than the slot
wait (15 seconds) keeps its slot, so a third parallel connection to the same host (long image layer
downloads in parallel, for example) may be refused with `slots_full`, and a vendor's 429 makes the
run partial like a target's. Standard and Fast are rarely affected; a sensor that pulls large images
on Gentle may see such gaps.

- Call `toolhost.RunOptions{HostBudget: &budget}`.
- Tools that run through the compat scanner (`toolcompat.AsScanner`: adapter directories and
  `Kit.AddTool`) get the scan's budget (`core.ScanOptions.HostBudget`); when the scan carries none, the
  lowest of the sensor's pacing level, Standard and the local policy's per-host ceiling
  (`rate.max_host_rps`, `rate.max_host_inflight`) (`adapt.FallbackBudget`), never above the sensor's
  level or the operator's ceiling. A tool described only by its manifest is held by the forwarder like any other and has
  its rate key (`safety.rate_param`) lowered to the budget.
- A retest runs under its command's budget (`adapt.WithHostBudget` on the context the kit's retest
  command passes), resolved like a scan's: the lowest limit wins. Without one it falls back like a scan.
- A port scan is paced in packets per second by the level of the budget (`Pacing.ProbePPS`), through the
  tool's own rate setting. Its caller still passes the budget and sets `RunOptions.PortProbes`: the
  forwarder then does not hold the task to the budget's requests per second (a port probe is not a
  request). Only a port scanner compiled into a sensor sets it; an adapter that scans ports through the
  compat scanner is held to the budget's requests per second like any tool, and is slow.
- A value under a tool's rate key that is not a rate of at least one a second (zero, a negative number,
  a string, `null`) is replaced by the tool's default or the budget, whichever is lower: it never
  reaches a tool that could read it as "no limit".

Which tools of a sensor run under the budget is that sensor's to list; the OpenCTEM sensor's list is in
its `docs/REFERENCE.md` ("Per-host budget") and is checked by a test.

## Back-off

`adapt.HostRate` reacts to what the task's **tool** met. The table is about a host name; for the address
names are reached at, each of these signals lowers the address's rate and nothing else ("An address only
slows" above).

| signal on the tool's own traffic | effect |
|---|---|
| 429, 503, a vendor's rate-limit page (read on plain HTTP or on a connection the forwarder terminates) | the host's rate is halved (at most once per window); a `Retry-After` is waited out (capped at 5 minutes; connections are refused instead of held when it is longer than 10 seconds) |
| five such answers in a row with no ordinary HTTP answer between them (counted at most once a second) | the host's breaker opens for 15 s (then 30 s; at least as long as `Retry-After` asked); the host is a coverage gap `throttled` whose detail holds only counts: `throttled by target: 429=12 503=1 retry_after=30s backoffs=5 circuit_opens=1 opened_by=tool_http` |
| a vendor's challenge or block page | the host is a gap `blocked` from the first answer |
| a timeout, a refused connection on a port that answered before, a failed TLS handshake | the rate is halved; five in a row open the breaker |
| a reset on a connection the host accepted | refuses that request; twenty in a row are a block |
| a clean window after a back-off | a tenth of the budget is added back; a breaker that opened is closed by the first request that is answered after its open time |
| three breaker openings in one task | the host is given up for the task |

A run that met push-back completes **partial**: the hosts are listed as coverage gaps and everything the
tool delivered is kept. Nothing is dropped because a host throttled. `host_stats[].opened_by` records the
evidence that opened a breaker: `tool_http`, `tool_connection` or `canary_and_tool_connection`.

### HTTPS without interception: the canary

On HTTPS it passes through, the forwarder sees dials, resets and how a tunnel ended, never an answer.
`adapt.Canary` reads one for it. While a confined task runs, the tool host sends a `GET /` to each origin
a target names by an `http` or `https` URL whose connections the forwarder passes through, every 10
seconds (every 3 seconds after push-back).

- **The request is fixed.** `GET /`, no query, no body, and one header besides `Host`: the sensor's own
  `User-Agent` (`useragent.String`). Nothing a job or a platform setting says changes it: not the job's
  identification headers, not a User-Agent rotation, not an identification query string. Only the origin
  comes from the job's signed targets. A target that wants to recognise the scanner by it can; that is
  what a published identification is for.
- **It travels the tool's own way out**: the task forwarder's dial path (`Forwarder.DialTarget`), with the
  same scope check (address literals included), the addresses pinned at admission (no name is resolved
  again) and the job's proxy pool. A task without a forwarder gets no canary: the runtime shares no way
  out with the tool there, so a request of its own would leave by another route than the tool's.
- **One per address.** Names of the task that are reached at one address get one canary between them, and
  what it is answered is reported to the address, so it slows all of them (and only slows them).
- It waits while the host's breaker is open or the host asked to wait (once the open time is over, an
  ordinary answer to it closes the breaker), takes a token of the host's
  rate when one is free and never waits behind the tool's requests (so it adds at most one request every 3
  seconds, and holds none of the host's connection slots). It follows no redirect and is never retried.

**What the canary's answer does.** A 429 or 503, a vendor's rate-limit, block or challenge page, a 403
from an origin that served the same request before, and a reset or timeout from an origin that served it
before each **halve the host's rate** (down to the floor of one request a second). Besides that, the
canary by itself only reports:

- it never opens a breaker, never starts a cooldown for the tenant's other tasks, never refuses or holds
  a connection and never stops a tool. Its `Retry-After` is counted in the result and is not waited out
  by the tool's connections. A target can answer the recognisable canary differently from the tool; if
  the canary's answer alone could stop a scan, a target could end its own scan with one answer;
- **an observed throttle.** Two rate-limit answers in a row (429, 503, a vendor's rate-limit page; no
  ordinary answer to the canary between them) make the host a coverage gap `throttled` with
  `"observed": true` and `canary_pushback` in its detail and its `host_stats` entry. It stops nothing:
  the scan of the host goes on at its lowered rate and the run completes partial. It is there because
  what the tool was answered on those unread connections may have been the limit and not the
  application, and whoever reads the result (a platform that holds the findings of a throttled host for
  a retest) must be able to see that. A refusal, a reset or a timeout of the canary alone is not
  reported this way. A target can make its own run report it by limiting only the canary; that marks
  the run's findings for that host as taken under throttling and takes nothing away;
- the breaker opens when the canary's push-back and **connection-level evidence from the tool's own
  traffic** come together: three failed or reset connections of the tool within 30 seconds of push-back on
  the canary (`opened_by: canary_and_tool_connection`). That is what a host that throttles HTTPS shows on
  tunnels nobody reads.

What the canary covers, and what it does not:

| covered | not covered |
|---|---|
| a host that rate-limits or blocks the scanner's address as a whole: the rate comes down on 429, 503, `Retry-After`, vendor block, challenge and rate-limit pages, resets and timeouts of a request the host served before; rate limits are also reported as an observed throttle | a host that answers the tool's HTTPS requests with 429 and closes each connection cleanly while it serves the canary: nothing sees it. When it limits the canary too, the rate is at the floor and the host is reported as an observed throttle; the breaker stays closed (there is no evidence from the tool's own traffic) |
| HTTPS and plain HTTP in confined runs, a job's proxy pool | unconfined runs (no canary) |
| | a limit that applies only to the paths, payloads or session of the tool's own requests |
| | a host no target names by an `http(s)` URL (a bare host name or `host:port`): the scheme and port are not known, and a canary never contacts an origin the job did not name |
| up to 64 hosts per task | further hosts of the task (they still run under the budget) |
| a 403 from an origin that answered the same request before | an origin whose root is forbidden from the first request on (read as an ordinary answer) |
| | a host whose certificate does not verify (self-signed, expired, another name): the canary verifies certificates and reads nothing from such a host, so what an unauthenticated peer answers never steers the rate |
| | latency growth as a congestion signal (not implemented) |

## What the result says

`metadata.target_rate` of a job result (`adapt.Summary`) carries, besides the rates:

```json
{
  "budget": {"level": "standard", "rps": 20, "inflight": 8,
             "won_by": {"rps": "sensor_level", "inflight": "sensor_level"},
             "clamped": [{"key": "rps", "asked": 100, "to": 20, "by": "sensor_level", "source": "job"},
                         {"key": "inflight", "asked": 25, "to": 8, "by": "sensor_level", "source": "job"},
                         {"key": "rate_limit", "asked": 150, "to": 20, "by": "host_budget"}]},
  "backoffs": 4, "circuit_opens": 1,
  "host_stats": [{"host": "192.0.2.10", "address": true, "rate": 2.5, "min": 1, "backoffs": 4},
                 {"host": "a.example.com", "rate": 2.5, "min": 1, "backoffs": 4, "circuit_opens": 1,
                  "http_429": 12, "http_503": 1, "retry_after_seconds": 30, "opened_by": "tool_http"},
                 {"host": "b.example.com", "rate": 1, "min": 1, "backoffs": 3, "http_429": 6, "canary_pushback": 6}],
  "gaps": [{"host": "a.example.com", "reason": "throttled", "detail": "throttled by target: 429=12 503=1 ..."},
           {"host": "b.example.com", "reason": "throttled", "observed": true,
            "detail": "throttled by target: 429=6 canary_pushback=6 backoffs=3 circuit_opens=0"}],
  "canary": {"hosts": 2, "probes": 14, "pushback": 6, "held": 3}
}
```

- A gap with `"observed": true` is the canary's observation of rate limits on a host whose breaker never
  opened: the host was scanned to the end, at a lowered rate. A gap `slots_full` is a host one of whose
  connections found no connection slot (the sensor's own bound, above).

- `budget.won_by` names the limit that set each number. `budget.clamped` lists what was asked for and did
  not apply: the sensor's level or the job's budget where a lower limit won (`source` says which of them
  asked, `by` which limit won), and a rate or concurrency setting of the scan above the budget (`key` is
  the setting, `by` is `host_budget`).
- `host_stats` lists the hosts that were slowed or opened (at most 100), and the addresses several names
  share. `pacing_limited` is set when no forwarder was in the path.
- The members are additive: a receiver that does not know them ignores them.

The task's log has one line with the budget, the limit that set it and the counts, one per value that did
not apply and one per host that pushed back. Host names appear there as they do in the existing
rate-change lines; nothing a host sent is logged.

`toolhost.Pacing()` returns the process totals (tasks under a budget, tasks whose pacing was limited,
back-offs, breaker openings, throttled hosts, values that did not apply) and
`toolhost.NewPacingCollector()` exposes them as Prometheus counters `openctem_sensor_pacing_*`, without
labels.

## Version skew

The sensor verifies a signed statement strictly: **a statement with a member it does not know is
refused** (the decoder disallows unknown fields), and so is a statement whose `pacing` member it cannot
read. That is deliberate: a limit a sensor cannot read must never be dropped silently.

- **A new sensor with an older platform.** The platform signs no `pacing` member: every job runs at the
  sensor's level. Nothing the platform has to change.
- **A new platform with an older sensor.** The platform sends the `pacing` member **only to a sensor that
  reports the capability** `pacing.budget@1` (`core.CapabilityHostBudget`) in its latest heartbeat. A
  sensor that does not report it gets the statement without the member and runs at its own level.
- **A sensor that does not verify job signatures.** A job's budget is read only from a verified
  statement, so a sensor with no pinned job key ignores it and runs at its own level. Such a sensor must
  not report the capability: a platform would otherwise believe a signed Gentle is honoured there. The
  OpenCTEM sensor reports it only when a job key is pinned.
- **A sensor downgraded between its heartbeat and the claim.** The platform still believes the capability
  and signs the member; the older binary refuses the statement and the job fails on that sensor with the
  refusal reason `malformed` (the detail names the unknown field). It does not run unpaced: it does not
  run at all. The platform
  should then: drop the capability from what it holds for that sensor as soon as the refusal arrives (and
  at the latest on the sensor's next heartbeat, which no longer reports it); re-queue the job, excluding
  the refusing sensor as for any refused job; and sign the retry for the sensor that takes it according to
  the capabilities that sensor reports then. It must not retry the same statement on the same sensor.
- The local policy keys `rate.max_host_rps` and `rate.max_host_inflight` are additive keys of policy
  schema v1. A sensor from before them refuses a policy file that names them (an unknown key), as it does
  for any key it does not know.

## Security notes

- **Lowest limit wins.** No job, signed or not, raises what a host gets above the sensor's level, the
  operator's ceiling or the hard ceiling. The hard ceiling is a constant.
- Only the verified signed statement carries a job's budget. The command's unsigned fields, the payload,
  the settings layers and a tool's config can only lower what a tool sends.
- Back-off cannot be turned off, by a job or by the operator.
- The canary's request is fixed and dials only what the task's scope admits, on the tool's own path; a
  target cannot stop a scan through it.
- The budget is held per canonical host and, with a forwarder, per address: spelling a host differently or
  giving one server many names does not multiply it.
- One name cannot deny another: the address names share has a rate and connection slots, and no breaker,
  hold or cooldown. What one name answers slows the other names of its address and never stops them.
- No tool that can connect to its targets (network `targets`, `egress-proxy`, or `vendor` with a target
  among its vendor hosts) starts without a budget: the tool host refuses it, on every path.
- The connections open to a host never exceed its slots; an idle one is closed for a connection that
  needs its slot.
- A connection the budget's slots refused is reported as a coverage gap of its host (`slots_full`), never
  as a host with nothing found and never as the host pushing back.
- What is not held is stated above and is not hidden: the requests of a client that packs several into
  one TLS record (bounded in bytes), the streams in flight on one HTTP/2 connection, a slow first answer
  on a tunnel after other bytes from the host (counted as idle after five seconds), and every
  bound but the tool's own flags when no forwarder is in the path.
- Nothing rotates addresses or changes the identification to get past a block. The only reactions are to
  slow down, to stop sending to a host whose breaker opened, and to report.
