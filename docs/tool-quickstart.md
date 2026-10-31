# Write a tool in 15 minutes

A tool is how anyone, a vendor or a tenant, adds a scanner, a connector, a parser or an enricher to an
OpenCTEM sensor. The contract is small and the same for every tool, ours included:

- **Two methods.** `Manifest()` says what the tool is; `Run(ctx, task)` does one task. `tool.New` builds both from a
  `tool.yaml` file and one typed function.
- **Out of process.** The sensor starts your program as its own sandboxed process and speaks the adapter protocol
  with it. `adapter.Serve` is all of that on your side. Any language works; this page uses Go.
- **Confined.** Targets arrive signed from the platform and are re-checked against the sensor's local policy. Your
  program has no network of its own: its only way out is the sensor's forwarder, which reaches the task's targets.

This page builds [`examples/hello-tool`](../examples/hello-tool), which is complete and runs in CI. The reference
for every field is [Writing a tool](https://docs.openctem.io/developers/tool-authoring/); the same walk-through for
a Python tool is [Build your first tool](https://docs.openctem.io/developers/build-your-first-tool/).

You need Go 1.26 or later.

## 1. Install the SDK and the CLI

```bash
V=v0.41.0                                  # the SDK release you pin
go install github.com/openctemio/sdk-go/cmd/openctem@$V
openctem version
```

For a machine without Go, release binaries and their cosign-verified checksums are described in
[docs/tools/cli.md](tools/cli.md). In your tool's module, `go get github.com/openctemio/sdk-go@$V`.

## 2. Scaffold

```bash
openctem tool init --kind go --capability vuln.templates@1 --name hello-tool hello-tool
cd hello-tool
```

A tool implements **capabilities** from a closed list ([capabilities.md in
ctis](https://github.com/openctemio/ctis/blob/main/docs/capabilities.md)). The capability fixes the phase, the
minimum tier, the target types the tool may take and the output every report must carry, and it is how a scan finds
your tool. `init` writes `tool.yaml`, `main.go`, a self-test fixture, a `Makefile`, a CI workflow and a
`pack.yaml` (step 8). It never overwrites a file.

## 3. The manifest: `tool.yaml`

The runtime trusts this file and never the program's description of itself, and refuses unknown keys. It is the one
place every fact about the tool is written.

```yaml
apiVersion: openctem.io/tool/v1
name: hello-tool                  # unique per sensor: ^[a-z][a-z0-9-]{1,62}$
version: "0.1.0"                  # semantic version of your tool
class: target-scan                # target-scan | connector | parser | enricher
tier: T1                          # T0 passive, T1 active, T2 intrusive
implements:                       # the capabilities it serves, with the param mapping
  - capability: vuln.templates@1
    params:
      rate: {}                    # the platform's standard "rate" param reaches config key "rate"
consumes: [http_service, website, web_application]       # input types
produces: ["finding:misconfiguration"]                   # anything else is refused
config:                           # typed parameters, a closed JSON Schema subset
  additionalProperties: false
  properties:
    rate: {type: integer, minimum: 1, maximum: 100, x-octm-scope: scan}
  type: object
permissions:
  network: targets                # none | targets | resolver | egress-proxy | vendor
resources: {}
safety:
  rate_param: rate                # the sensor's rate cap reaches the tool through this key
run:
  argv: [./bin/hello-tool]        # how the sensor starts it
selftest:                         # the fixtures step 5 runs
  - {name: missing-header, task: fixtures/task.json, expect: fixtures/expect.ctis.json}
protocol: {min: 1}                # adapter protocol versions you speak
```

Rules that matter:

- `produces` is a promise: a finding of another type is refused. `consumes` narrows the targets the runtime admits.
- Parameters are `config` properties. A key with `x-octm-scope: scan` may be set by a scan; every other key is for
  the sensor's administrator. A key the schema does not list never reaches your code, and a secret is never a
  config key: declare it under `permissions.credentials`.
- `class`, `tier` and `network` are requests. The platform assigns the effective tier and may raise it, never lower it.

`openctem tool validate .` checks the file; every error names the field as a JSON pointer.

## 4. The two methods and the builder

```go
//go:embed tool.yaml
var manifest []byte

type config struct {
	Rate int `json:"rate"`
}

func main() { adapter.Serve(newTool()) }

func newTool() tool.Tool {
	m, err := tool.LoadManifest(manifest)
	if err != nil {
		panic(err)
	}
	return tool.New(m, run)   // tool.Tool: Manifest() and Run(ctx, task)
}

func run(ctx tool.Context, task tool.Task, _ config) error {
	for _, t := range task.Targets {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, t.URL(""), nil)
		resp, err := ctx.HTTP().Do(req)          // the only way out of the sandbox
		if err != nil {
			ctx.TargetError(t, tool.Unreachable(err))
			continue
		}
		_ = resp.Body.Close()
		if resp.Header.Get("X-Content-Type-Options") == "" {
			if err := ctx.Emit().Finding(t, ctis.Finding{
				Type: ctis.FindingTypeMisconfiguration, RuleID: "hello-tool/xcto-missing",
				Title: "X-Content-Type-Options header missing", Severity: ctis.SeverityLow,
				Web: &ctis.WebLocation{URL: t.URL(""), Method: http.MethodGet},
			}); err != nil {
				return err
			}
		}
		ctx.TargetDone(t)
	}
	return nil
}
```

The full file, with the cancel and skip handling, is [`examples/hello-tool/main.go`](../examples/hello-tool/main.go).

- **Config.** `tool.New` validates a task's configuration against the manifest's schema, fills the defaults and
  decodes it into your struct, refusing unknown keys. With no `config:` in the manifest it derives the schema from
  the struct tags (`json`, `default`, `min`, `max`, `enum`, `scope`, ...). Pass `map[string]any` to read it loosely.
- **Report every target once**: `ctx.TargetDone`, `ctx.TargetError` (with `tool.Unreachable`, `tool.Invalid`, ...) or
  `ctx.TargetSkipped`. Return an error from `Run` only when the task as a whole failed.
- **Logs** go through `ctx.Log()`, never to standard output (it is the protocol channel).
- **Secrets**: `ctx.Secret(name)`, only for credentials the manifest declared and the operator stored. A `Secret`
  prints as `[REDACTED]` everywhere.

## 5. Run it locally and test it

No platform is needed. The CLI runs your program through the same host and sandbox a sensor uses.

```bash
make build                                        # go build -o bin/hello-tool .
python3 -m http.server 8000 --bind 127.0.0.1 &
openctem tool run . --target http://127.0.0.1:8000/@http_service --format table
openctem tool run . --target http://127.0.0.1:8000/@http_service --format ctis   # the report a sensor sends
openctem tool test --update . ; openctem tool test .     # record, review, then check the fixtures
openctem tool test --capability --scope --fuzz 30s .     # capability suite, scope check, fuzzing
```

`--scope` gives the tool one target while another address listens nearby: any connection to anything else fails
the check and names the destination.

In `go test`, three layers, all in [`examples/hello-tool/main_test.go`](../examples/hello-tool/main_test.go):

```go
// 1. In-process, with the rules the runtime applies (declared outputs, CTIS validity, size limits).
res := testkit.Run(t, newTool(), tool.Task{Targets: []tool.Target{{Ref: "t1", Type: "http_service", Value: url}}})
res.RequireStatus(t, tool.StatusOK)

// 2. The built program against adapter protocol v1: handshake, describe equals tool.yaml, stdout is
//    protocol only, exit on EOF, cancel, and the self-test fixtures through the runtime's own host.
conformance.RunToolSuite(t, "path/to/installed/tool.yaml", conformance.ToolSuiteOptions{})

// 3. The report is accepted by a platform that implements the results contract.
fp := conformance.NewFakePlatform(true)
defer fp.Close()
c := client.New(&client.Config{BaseURL: fp.URL(), APIKey: fp.APIKey, Protocol: client.ProtocolV2})
pushed, err := c.PushFindings(ctx, res.Report)       // fp.Reports()[pushed.ReportID].Committed == true
```

`FakePlatform` records every request and can inject each failure class, so the same tests also prove how a
sensor-side component behaves when the platform misbehaves. The tests listen on loopback, which the SDK refuses
by default: set `httpsec.AllowLoopback = true` in `TestMain`, as the example does.

## 6. Results: findings and assets

Emit records through `ctx.Emit()`; each one is checked as it is emitted and a refused record returns an error:

| Call | Use |
|---|---|
| `Finding(target, ctis.Finding{...})` | a finding on the target's asset. Needs `Type` (declared in `produces`), `Title`, `Severity`, and the fields the capability requires (for a web check `RuleID` and `Web.URL`). |
| `Asset(ctis.Asset{...})` | a newly discovered asset (`produces: ["asset:<type>"]`) |
| `Dependency`, `Endpoint` | software components and web endpoints |
| `Report(*ctis.Report)` | a whole CTIS report, for a tool that already has one |

You do not set the asset reference or the provenance: the runtime attaches the finding to the target's
asset and stamps the tool, version, descriptor digest and sandbox state. Anything you write into a finding is
untrusted data on the platform's side too: it is validated again there, strictly.

## 7. Egress, scope and what the runtime enforces

You declare needs in `permissions`; the effective permission is your manifest intersected with the sensor's local
policy and the job.

| You declare | What happens |
|---|---|
| `network: targets` | the task's targets only, through the egress forwarder. A direct connection fails. |
| `network: none` (parsers, enrichers) | no network at all |
| `network: resolver` | DNS questions about the targets, answered by the sensor's resolvers; no connection to any host |
| `network: vendor` and `vendor_hosts` | the named vendor API hosts only, with the credentials the operator stored |
| `filesystem: workdir` (default) | the task's private directory only |
| `linux_caps: [NET_RAW]` | granted only when the sensor's local policy allows it |

Targets are never your concern to authorize: the platform signs the job, the sensor verifies the signature and
re-checks every target against its own local policy (allowed ranges, rate caps, `tools.allow`), and checks every
record you emit again before it leaves. A tool cannot widen any of it, and a tool that tries is stopped, not
trusted. Honour the rate: read it from your config and keep to it.

## 8. Package and ship

`pack.yaml` makes the tool a pack, the unit that is versioned, built into an image, signed and delivered:

```bash
openctem tool validate .
openctem tool build . --output ./pack-image              # reproducible OCI image, no container daemon
openctem tool build . --push registry.example.com/acme/hello-tool:0.1.0     # prints the index digest
```

- **Container image.** Cross-compile your program per platform into `.build/<os>-<arch>/bin/hello-tool` and the
  build puts it in the pack layer. The digest, never a tag, is what you sign (keyless cosign from CI, which the
  generated CI workflow does on a `vX.Y.Z` tag) and what a tenant pins. Details: [tool-packs.md](tool-packs.md).
- **Plain binary.** Ship `tool.yaml` and the program as an archive with a `SHA256SUMS` file, and sign that file. The
  installer verifies the checksum before copying anything. The program should be a static binary (`CGO_ENABLED=0`),
  because the published sensor image has no shell and no interpreter.

## 9. How a tenant installs and approves it

1. **Install.** Put the tool directory (`tool.yaml`, `bin/hello-tool`) under a directory listed in the sensor's
   `SENSOR_ADAPTER_DIRS`, owned by root or the sensor's user, not writable by group or others, with no symbolic
   links, and restart the sensor. `openctemio-sensor tools manifests` lists what loaded and why anything was
   refused.
2. **It joins the catalog.** The sensor reports the tool's descriptor; the platform keeps it when it hashes to its
   digest and is a valid contract. It appears under **Settings > Scanning > Tools**, enabled. Nothing in the
   platform changes.
3. **Approve.** A tool the platform does not know is **unverified** and runs as **T2** whatever tier it asks for.
   The tenant's administrator allows it by granting the (Trusted) sensor T2 and having scope that allows T2 probes,
   reviews its options on the sensor's **Tool settings** tab and can switch it off at any time. Settings travel in
   the signed job, so nobody can alter them in transit.
4. **Use.** A workflow step pinned to `hello-tool`, or a step naming `vuln.templates`, runs it. Findings carry the
   tool and descriptor digest as provenance.

The tenant-facing detail is [How the tool reaches your organization](https://docs.openctem.io/developers/tool-authoring/#how-the-tool-reaches-your-organization).

## 10. Versions and compatibility

- **Your tool's `version`** is yours: `openctem tool diff <old> <new>` fails when a change needs a bigger bump than you
  made (narrowing what the tool takes or emits, raising its tier or adding a required config key is a new major).
  A published pack version is immutable.
- **`protocol: {min: 1}`** is the adapter protocol range you speak, and `sdk: {min: ...}` (or `requires.sdk` in
  `pack.yaml`) names the oldest SDK that understands every key you use.
- **The platform owns compatibility.** It reads each sensor's reported versions and tool contracts and decides what
  can run where. A sensor, an SDK and a tool are released independently: a new SDK or sensor release never requires
  a change to the platform, and a tool never needs the platform's release. See [STABILITY.md](STABILITY.md) for what the SDK
  keeps stable and how a break is announced.
- Pin the SDK release your tool is built and tested against; upgrade when you want a feature, not because you must.
