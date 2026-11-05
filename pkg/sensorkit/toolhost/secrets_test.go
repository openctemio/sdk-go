package toolhost

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/contract/secretref"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// Values the tests deliver; each is long enough to be scrubbed.
const (
	platShodan = "plat-shodan-key-0123456789"
	locShodan  = "loc-shodan-key-9876543210"
	locVT      = "loc-virustotal-key-55555"
	locAlpha   = "loc-alpha-generic-7777"
)

// secretTool is a passive target-scan tool of network vendor (the shape of
// subfinder: its name is the one the provider registry lists). It reports
// which slots it received (by a short prefix), then tries every way a
// value could leak: it logs each value raw and encoded, puts the encodings
// in a finding, writes a file into an artifact, and checks its own argv,
// environment, /proc/self/environ and /proc/self/cmdline. The target
// "fail.example" makes it fail after writing a secret file, "hang.example"
// makes it wait to be canceled.
var secretTool = tool.New(tool.Manifest{
	Name: "subfinder", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1,
	Consumes: []string{"domain_name"}, Produces: []string{"finding:misconfiguration"},
	Permissions: tool.Permissions{Network: tool.NetVendor, VendorHosts: []string{"crt.sh"}, Credentials: []tool.CredentialReq{
		{Name: "shodan", Kind: "api_key"}, {Name: "virustotal", Kind: "api_key"}, {Name: "alpha", Kind: "api_key"}}},
}, func(ctx tool.Context, task tool.Task, _ tool.NoConfig) error {
	var got, values []string
	for _, name := range []string{"shodan", "virustotal", "alpha"} {
		if k, err := ctx.Secret(name); err == nil {
			v := k.Reveal()
			values = append(values, v)
			got = append(got, name+"="+v[:4])
		}
	}
	leak := "clean"
	for _, v := range values {
		if strings.Contains(strings.Join(os.Args, " "), v) || strings.Contains(strings.Join(os.Environ(), "\n"), v) {
			leak = "leak"
		}
		if runtime.GOOS == "linux" {
			for _, f := range []string{"/proc/self/environ", "/proc/self/cmdline"} {
				if b, err := os.ReadFile(f); err == nil && strings.Contains(string(b), v) {
					leak = "leak"
				}
			}
		}
	}
	var encoded []string
	for _, v := range values {
		basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:"+v))
		encoded = append(encoded, v, base64.StdEncoding.EncodeToString([]byte(v)), base64.RawURLEncoding.EncodeToString([]byte(v)),
			url.QueryEscape(v), basic, `{"Authorization":"`+basic+`"}`)
		ctx.Log().Info("key "+v, "b64", base64.URLEncoding.EncodeToString([]byte(v)), "header", basic)
	}
	path, err := tool.WriteSecretFile(ctx.Workdir(), "provider-config.yaml", []byte(strings.Join(values, "\n")))
	if err != nil {
		return err
	}
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	ctx.Log().Info("secret file", "path", path, "mode", fmt.Sprintf("%o", fi.Mode().Perm()))
	w, err := ctx.Artifact("dump.txt", "text/plain")
	if err != nil {
		return err
	}
	_, _ = w.Write([]byte(strings.Join(encoded, "\n")))
	if err := w.Close(); err != nil {
		return err
	}
	for _, t := range task.Targets {
		switch t.Value {
		case "fail.example":
			return errors.New("failed on purpose")
		case "hang.example":
			<-ctx.Done()
			return ctx.Err()
		}
		if err := ctx.Emit().Finding(t, ctis.Finding{Type: "misconfiguration", RuleID: "r1", Severity: "info",
			Title:       "got " + strings.Join(got, ",") + " env=" + leak,
			Description: strings.Join(encoded, " | ")}); err != nil {
			return err
		}
		ctx.TargetDone(t)
	}
	return nil
})

// fakeFetch is the platform's answer to a task's secrets fetch.
type fakeFetch struct {
	mu    sync.Mutex
	calls [][]string
	err   error
	// values by ref id; a ref without one is answered missing.
	values map[string]string
}

func (f *fakeFetch) Secrets(_ context.Context, cmdID, _ string, set secretref.Set, refs []string) (*secretref.Answer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, refs)
	if f.err != nil {
		return nil, f.err
	}
	ans := &secretref.Answer{CommandID: cmdID, LeaseEpoch: 1, IssuedAt: time.Now()}
	for _, id := range refs {
		ref, _ := set.Lookup(id)
		v, ok := f.values[id]
		if !ok {
			ans.Missing = append(ans.Missing, secretref.Missing{ID: id, Reason: secretref.MissingNotSet})
			continue
		}
		raw, _ := json.Marshal(secretref.ProviderKey{Key: v})
		ans.Secrets = append(ans.Secrets, secretref.Secret{ID: id, Kind: ref.Kind, Value: raw, Provenance: secretref.ProvenanceTenant})
	}
	if err := ans.Check(set, cmdID, 1, refs, time.Now()); err != nil {
		return nil, err
	}
	return ans, nil
}

func (f *fakeFetch) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// providerRef is the job's ref k<n> for provider id.
func providerRef(id, n, local string) secretref.Ref {
	return secretref.Ref{ID: "k" + n, Kind: secretref.KindProviderKey, Class: secretref.ClassProvider, Ref: id, Slot: id,
		Audience: []string{secretref.AudienceProvider(id)}, Consumer: secretref.ConsumerTool, Local: local}
}

func jobSet(local string, refs ...secretref.Ref) *secretref.Set {
	s := &secretref.Set{V: secretref.Version, Local: local, Refs: refs}
	if err := s.Validate(); err != nil {
		panic(err)
	}
	return s
}

const testCmd = "0193a3f2-0000-7000-8000-000000000002"

func secretCtx(set *secretref.Set, shared bool, f core.SecretsFetcher) context.Context {
	return core.WithJobSecrets(context.Background(), core.NewJobSecrets(testCmd, set, shared, f))
}

// landlocked is a host whose sandbox has Landlock (or not).
func landlocked(shared, ll bool) *Host {
	st := executor.Status{}
	if ll {
		st.Landlock = 4
	}
	return &Host{Shared: shared, Backend: statusBackend{st: st}}
}

func credMap(ts *taskSecrets) map[string]string {
	out := map[string]string{}
	for _, c := range ts.creds {
		out[c.Name] = c.Value
	}
	return out
}

// SECURITY: the local precedence matrix. The platform's value wins; a
// local value fills a slot only where the signed policy allows it ("allow"
// or "only"); "only" never asks the platform; "never" ignores the local
// value; a shared sensor never uses a local value, even when the job says
// "allow"; a job without a verified list gets no platform value and, on an
// organization's sensor only, the local values.
func TestSecretsLocalPrecedenceMatrix(t *testing.T) {
	m := secretTool.Manifest()
	local := map[string]string{"shodan": locShodan, "alpha": locAlpha}
	fetchWith := func() *fakeFetch { return &fakeFetch{values: map[string]string{"k1": platShodan}} }
	cases := []struct {
		name      string
		shared    bool // the host's own view
		jsShared  bool // the poller's view
		set       *secretref.Set
		noJob     bool
		want      map[string]string
		wantFetch int
	}{
		{"org, allow, platform value", false, false, jobSet("allow", providerRef("shodan", "1", "allow")), false,
			map[string]string{"shodan": platShodan, "alpha": locAlpha}, 1},
		{"org, never: no local value", false, false, jobSet("never", providerRef("shodan", "1", "never")), false,
			map[string]string{"shodan": platShodan}, 1},
		{"org, only: platform not asked", false, false, jobSet("allow", providerRef("shodan", "1", "only")), false,
			map[string]string{"shodan": locShodan, "alpha": locAlpha}, 0},
		{"shared host, job says allow", true, false, jobSet("allow", providerRef("shodan", "1", "allow")), false,
			map[string]string{"shodan": platShodan}, 1},
		{"shared identity, job says allow", false, true, jobSet("allow", providerRef("shodan", "1", "allow")), false,
			map[string]string{"shodan": platShodan}, 1},
		{"org, no verified list", false, false, nil, false, map[string]string{"shodan": locShodan, "alpha": locAlpha}, 0},
		{"shared, no verified list", true, true, nil, false, map[string]string{}, 0},
		{"org, not a platform job", false, false, nil, true, map[string]string{"shodan": locShodan, "alpha": locAlpha}, 0},
		{"shared, not a platform job", true, false, nil, true, map[string]string{}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := fetchWith()
			ctx := secretCtx(tc.set, tc.jsShared, f)
			if tc.noJob {
				ctx = context.Background()
			}
			ts, ierr := landlocked(tc.shared, true).secretsFor(ctx, m, tool.Task{ID: "t1"}, local)
			if ierr != nil {
				t.Fatal(ierr)
			}
			if got := credMap(ts); fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Fatalf("delivered %v, want %v", got, tc.want)
			}
			if f.count() != tc.wantFetch {
				t.Fatalf("fetched %d times, want %d", f.count(), tc.wantFetch)
			}
		})
	}
}

// SECURITY: a fetch that fails (a refusal, a 404 with or without a problem
// document, a gateway error, an answer that does not open) gives no
// platform value and no other source: on a shared sensor nothing, on an
// organization's sensor the local value only where the signed policy says
// "allow". A required slot without a value fails the task, naming it.
func TestSecretsFetchFailureHasNoFallback(t *testing.T) {
	m := secretTool.Manifest()
	local := map[string]string{"shodan": locShodan}
	for _, ferr := range []error{errors.New("404 command_not_found"), errors.New("404 page not found (no problem document)"),
		errors.New("secrets: the answer does not open with this request's key")} {
		f := &fakeFetch{err: ferr}
		ts, ierr := landlocked(true, true).secretsFor(secretCtx(jobSet("never", providerRef("shodan", "1", "never")), true, f), m, tool.Task{}, local)
		if ierr != nil || len(ts.creds) != 0 || f.count() != 1 {
			t.Fatalf("shared, %v: delivered %v (%v)", ferr, credMap(ts), ierr)
		}
		ts, _ = landlocked(false, true).secretsFor(secretCtx(jobSet("allow", providerRef("shodan", "1", "never")), false, f), m, tool.Task{}, local)
		if len(ts.creds) != 0 {
			t.Fatalf("org, never, %v: delivered %v", ferr, credMap(ts))
		}
		ts, _ = landlocked(false, true).secretsFor(secretCtx(jobSet("allow", providerRef("shodan", "1", "allow")), false, f), m, tool.Task{}, local)
		if got := credMap(ts); got["shodan"] != locShodan {
			t.Fatalf("org, allow, %v: delivered %v", ferr, got)
		}
	}
	req := providerRef("shodan", "1", "never")
	req.Required = true
	_, ierr := landlocked(true, true).secretsFor(secretCtx(jobSet("never", req), true, &fakeFetch{err: errors.New("down")}), m, tool.Task{}, local)
	if ierr == nil || !strings.Contains(ierr.Detail, secretref.RefusalSecretMissing) || !strings.Contains(ierr.Detail, `"shodan"`) {
		t.Fatalf("a required slot without a value: %+v", ierr)
	}
}

// SECURITY: the gates on platform values. A tool that may reach any public
// host (egress-proxy) gets none and the platform is not asked; a provider
// key goes only to a tool of network vendor that its provider lists; a
// shared sensor without Landlock delivers none, an organization's sensor
// delivers with a warning.
func TestSecretsGates(t *testing.T) {
	base := secretTool.Manifest()
	set := jobSet("never", providerRef("shodan", "1", "never"))
	run := func(m tool.Manifest, h *Host, shared bool) (*taskSecrets, *fakeFetch) {
		t.Helper()
		f := &fakeFetch{values: map[string]string{"k1": platShodan}}
		ts, ierr := h.secretsFor(secretCtx(set, shared, f), m, tool.Task{}, nil)
		if ierr != nil {
			t.Fatal(ierr)
		}
		return ts, f
	}
	anyPublic := base
	anyPublic.Permissions.Network, anyPublic.Permissions.VendorHosts = tool.NetEgressProxy, nil
	if ts, f := run(anyPublic, landlocked(false, true), false); len(ts.creds) != 0 || f.count() != 0 {
		t.Fatalf("egress-proxy task: delivered %v, fetched %d", credMap(ts), f.count())
	}
	targets := base
	targets.Permissions.Network, targets.Permissions.VendorHosts = tool.NetTargets, nil
	if ts, f := run(targets, landlocked(false, true), false); len(ts.creds) != 0 || f.count() != 0 {
		t.Fatalf("targets task: delivered %v, fetched %d", credMap(ts), f.count())
	}
	other := base
	other.Name = "not-a-provider-tool"
	if ts, f := run(other, landlocked(false, true), false); len(ts.creds) != 0 || f.count() != 0 {
		t.Fatalf("a tool its provider does not list: delivered %v, fetched %d", credMap(ts), f.count())
	}
	if ts, f := run(base, landlocked(true, false), true); len(ts.creds) != 0 || f.count() != 0 {
		t.Fatalf("shared without Landlock: delivered %v, fetched %d", credMap(ts), f.count())
	}
	ts, f := run(base, landlocked(false, false), false)
	if credMap(ts)["shodan"] != platShodan || f.count() != 1 || !strings.Contains(fmt.Sprint(ts.lines), "Landlock") {
		t.Fatalf("org without Landlock: delivered %v, lines %v", credMap(ts), ts.lines)
	}
}

// An optional ref of a kind this sensor does not know is skipped (a
// required one refuses the whole job: core's JobSecretsFor tests).
func TestUnknownOptionalKindIsSkipped(t *testing.T) {
	ref := secretref.Ref{ID: "x1", Kind: "client_cert", Class: secretref.ClassTarget, Ref: "cred-1", Slot: "client_cert",
		Audience: []string{secretref.AudienceTargets}, Consumer: secretref.ConsumerTool, Local: secretref.LocalNever}
	f := &fakeFetch{}
	m := secretTool.Manifest()
	m.Permissions.Credentials = append(m.Permissions.Credentials, tool.CredentialReq{Name: "client_cert", Kind: "certificate"})
	ts, ierr := landlocked(true, true).secretsFor(secretCtx(jobSet("never", ref), true, f), m, tool.Task{}, nil)
	if ierr != nil || len(ts.creds) != 0 || f.count() != 0 {
		t.Fatalf("optional unknown kind delivered %v, fetched %d (%v)", credMap(ts), f.count(), ierr)
	}
}

// SECURITY: the network scope narrows to the audiences of delivered keys:
// a keyed host is admitted only when its key was delivered, and any other
// host stays refused; a local key in a provider slot adds its audience the
// same way; a key the provider's rules refuse is dropped, naming the slot
// only.
func TestSecretsNarrowTheVendorScope(t *testing.T) {
	m := secretTool.Manifest()
	set := jobSet("allow", providerRef("shodan", "1", "allow"), providerRef("virustotal", "2", "allow"))
	f := &fakeFetch{values: map[string]string{"k1": platShodan}}
	ts, ierr := landlocked(false, true).secretsFor(secretCtx(set, false, f), m, tool.Task{}, nil)
	if ierr != nil {
		t.Fatal(ierr)
	}
	if fmt.Sprint(ts.keyed) != "[api.shodan.io]" {
		t.Fatalf("keyed hosts %v", ts.keyed)
	}
	ts, _ = landlocked(false, true).secretsFor(secretCtx(set, false, &fakeFetch{}), m, tool.Task{}, map[string]string{"virustotal": locVT})
	if fmt.Sprint(ts.keyed) != "[www.virustotal.com]" {
		t.Fatalf("local key's keyed hosts %v", ts.keyed)
	}
	ts, _ = landlocked(false, true).secretsFor(secretCtx(set, false, &fakeFetch{}), m, tool.Task{}, map[string]string{"virustotal": "short"})
	if len(ts.creds) != 0 || len(ts.keyed) != 0 || strings.Contains(fmt.Sprint(ts.lines), "short") ||
		!strings.Contains(fmt.Sprint(ts.lines), "virustotal") {
		t.Fatalf("an invalid local key: %v %v %v", credMap(ts), ts.keyed, ts.lines)
	}
}

func outcomeText(t *testing.T, out *Outcome) string {
	t.Helper()
	rep, _ := json.Marshal(out.Report)
	var arts []string
	for _, a := range out.Artifacts {
		arts = append(arts, string(a.Data))
	}
	return fmt.Sprintf("%+v\n%s\n%s\n%s\n%+v", out.Logs, out.Stderr, rep, strings.Join(arts, "\n"), out.Err)
}

// leakForms are what must never leave a task for value v.
func leakForms(v string) []string {
	return []string{v, base64.StdEncoding.EncodeToString([]byte(v)), base64.RawURLEncoding.EncodeToString([]byte(v)),
		base64.URLEncoding.EncodeToString([]byte(v)), url.QueryEscape(v),
		base64.StdEncoding.EncodeToString([]byte("user:" + v))}
}

// SECURITY (end to end through the tool host): the platform's key and the
// local values reach the tool in its run message only (not in its argv or
// environment, also as /proc sees them); none of them, raw or encoded,
// reaches the logs, the records, the artifacts or the outcome; each task
// fetches once and nothing is kept between tasks; a secret file the tool
// writes is 0600 and gone with the task directory.
func TestTaskSecretsEndToEnd(t *testing.T) {
	f := &fakeFetch{values: map[string]string{"k1": platShodan}}
	set := jobSet("allow", providerRef("shodan", "1", "allow"), providerRef("virustotal", "2", "allow"))
	local := map[string]string{"shodan": locShodan, "virustotal": locVT, "alpha": locAlpha}
	for i := 0; i < 2; i++ {
		out, err := testHost(t).RunBuiltin(secretCtx(set, false, f), secretTool, tool.Task{Targets: oneTarget}, RunOptions{Credentials: local})
		if err != nil {
			t.Fatal(err)
		}
		if out.Status != tool.StatusOK || len(out.Report.Findings) != 1 {
			t.Fatalf("status %s err %v stderr %s", out.Status, out.Err, out.Stderr)
		}
		if got := out.Report.Findings[0].Title; got != "got shodan=plat,virustotal=loc-,alpha=loc- env=clean" {
			t.Fatalf("title %q", got)
		}
		all := outcomeText(t, out)
		for _, v := range []string{platShodan, locShodan, locVT, locAlpha} {
			for _, form := range leakForms(v) {
				if strings.Contains(all, form) {
					t.Fatalf("%q (a form of a delivered value) reached the outcome", form)
				}
			}
		}
		if len(out.Artifacts) != 1 || len(out.Artifacts[0].Data) == 0 || out.Artifacts[0].SHA256 != sha256Hex(out.Artifacts[0].Data) {
			t.Fatalf("artifact %+v", out.Artifacts)
		}
		path, mode := secretFileOf(t, out)
		if mode != "600" {
			t.Fatalf("secret file mode %s", mode)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("the task's secret file outlived the task: %v", err)
		}
	}
	if f.count() != 2 {
		t.Fatalf("two tasks fetched %d times", f.count())
	}
}

// secretFileOf is the path and mode the tool logged for its secret file.
func secretFileOf(t *testing.T, out *Outcome) (string, string) {
	t.Helper()
	for _, l := range out.Logs {
		if l.Msg == "secret file" {
			p, _ := l.Fields["path"].(string)
			m, _ := l.Fields["mode"].(string)
			return p, m
		}
	}
	t.Fatalf("no secret file line in %+v", out.Logs)
	return "", ""
}

// SECURITY: the task directory, with the secret file in it, is removed when
// the task fails and when it is canceled.
func TestSecretFileRemovedOnFailureAndCancel(t *testing.T) {
	local := map[string]string{"alpha": locAlpha}
	out, err := testHost(t).RunBuiltin(context.Background(), secretTool,
		tool.Task{Targets: []tool.Target{{Ref: "t1", Type: "domain_name", Value: "fail.example"}}}, RunOptions{Credentials: local})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status == tool.StatusOK {
		t.Fatalf("a failing task: %s", out.Status)
	}
	path, _ := secretFileOf(t, out)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("failed task: the secret file outlived the task: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err = testHost(t).RunBuiltin(ctx, secretTool,
		tool.Task{Targets: []tool.Target{{Ref: "t1", Type: "domain_name", Value: "hang.example"}}}, RunOptions{Credentials: local})
	if err != nil {
		t.Fatal(err)
	}
	path, _ = secretFileOf(t, out)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("canceled task: the secret file outlived the task: %v", err)
	}
}

// SECURITY: on a shared sensor no vendor namespace reaches a task, whatever
// the operator allowed or set; an organization's sensor keeps the tool's
// own.
func TestSharedSensorPassesNoVendorEnv(t *testing.T) {
	t.Setenv("PDCP_API_KEY", "operator-pdcp-key-123")
	core.SetScannerEnvAllowlist([]string{"PDCP_*"})
	defer core.SetScannerEnvAllowlist(nil)
	m := tool.Manifest{Name: "subfinder"}
	set := map[string]string{"SUBFINDER_X": "1", "PLAIN": "ok"}
	shared := &Host{Shared: true}
	if env := strings.Join(shared.taskEnv(m, set), "\n"); strings.Contains(env, "PDCP_") || strings.Contains(env, "SUBFINDER_") {
		t.Fatalf("shared sensor passed a vendor namespace: %s", env)
	}
	if got := shared.taskSetEnv(set); got["SUBFINDER_X"] != "" || got["PLAIN"] != "ok" {
		t.Fatalf("shared set env %v", got)
	}
	org := &Host{}
	if env := strings.Join(org.taskEnv(m, set), "\n"); !strings.Contains(env, "PDCP_API_KEY") {
		t.Fatalf("organization's sensor lost the tool's own namespace: %s", env)
	}
}
