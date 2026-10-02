package core

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/httpsec"
)

// sensorSecrets are variables a sensor process runs with that no scanner
// process may see: its platform key under every name it was ever read from,
// the outbox encryption key, enrollment tokens and generic credentials.
var sensorSecrets = []string{
	"API_KEY", "OPENCTEM_API_KEY", "AGENT_API_KEY", "SENSOR_API_KEY",
	"SENSOR_OUTBOX_KEY", "SENSOR_OUTBOX_KEY_FILE", "SENSOR_ENROLLMENT_TOKEN",
	"BOOTSTRAP_TOKEN", "GITHUB_TOKEN", "DB_PASSWORD", "AWS_SECRET_ACCESS_KEY",
}

func setSensorSecrets(t *testing.T) {
	t.Helper()
	for _, name := range sensorSecrets {
		t.Setenv(name, "must_not_leak_"+name)
	}
}

func assertNoSecrets(t *testing.T, where, out string) {
	t.Helper()
	if strings.Contains(out, "must_not_leak") {
		t.Errorf("%s: a sensor secret reached the scanner process:\n%s", where, out)
	}
	if !strings.Contains(out, "PATH=") {
		t.Errorf("%s: the child did not print its environment:\n%s", where, out)
	}
}

// Every way the SDK starts a scanner or probes one runs it with the
// allowlisted environment: none of the sensor's secrets reach it.
func TestScannerProcesses_DoNotSeeSensorSecrets(t *testing.T) {
	// One line, so CheckBinaryInstalled (first line only) sees it all.
	bin := fakeBinary(t, `env | tr '\n' ' '; echo`)
	setSensorSecrets(t)
	ctx := context.Background()

	if ok, out, err := VersionOutput(ctx, bin, "--version"); err != nil || !ok {
		t.Fatalf("VersionOutput: %v %v", ok, err)
	} else {
		assertNoSecrets(t, "VersionOutput", out)
	}
	if ok, out, err := CheckBinaryInstalled(ctx, bin); err != nil || !ok {
		t.Fatalf("CheckBinaryInstalled: %v %v", ok, err)
	} else {
		assertNoSecrets(t, "CheckBinaryInstalled", out)
	}

	res, err := ExecuteScanner(ctx, &ExecConfig{Binary: bin})
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecrets(t, "ExecuteScanner", string(res.Stdout))

	var streamed strings.Builder
	if _, err := StreamScanner(ctx, &ExecConfig{Binary: bin}, func(line string, _ bool) { streamed.WriteString(line) }); err != nil {
		t.Fatal(err)
	}
	assertNoSecrets(t, "StreamScanner", streamed.String())

	bs := NewBaseScanner(&BaseScannerConfig{Name: "fake", Binary: bin})
	if ok, out, err := bs.IsInstalled(ctx); err != nil || !ok {
		t.Fatalf("BaseScanner.IsInstalled: %v %v", ok, err)
	} else {
		assertNoSecrets(t, "BaseScanner.IsInstalled", out)
	}
	r, err := bs.Scan(ctx, t.TempDir(), &ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecrets(t, "BaseScanner.Scan", string(r.RawOutput))
}

// The environment builders themselves, in every proxy mode: the content
// environment (tool downloads) and the scanner environment with the proxy
// stripped or inherited.
func TestScannerEnvironments_DoNotCarrySensorSecrets(t *testing.T) {
	setSensorSecrets(t)
	t.Cleanup(func() { SetScannerProxyMode(ScannerProxyInherit) })
	proxy, _ := url.Parse("http://proxy.internal:3128")
	envs := map[string][]string{
		"content/environment": ContentEnviron(),
		"content/direct":      contentEnviron(os.Environ(), httpsec.ProxySetting{Mode: httpsec.ProxyDirect}),
		"content/url":         contentEnviron(os.Environ(), httpsec.ProxySetting{Mode: httpsec.ProxyURL, URL: proxy}),
	}
	for _, m := range []ScannerProxyMode{ScannerProxyInherit, ScannerProxyDirect} {
		SetScannerProxyMode(m)
		envs["scanner/"+string(m)] = ScannerEnviron()
	}
	for name, env := range envs {
		for _, kv := range env {
			if strings.Contains(kv, "must_not_leak") {
				t.Errorf("%s carries %s", name, kv)
			}
		}
	}
}
