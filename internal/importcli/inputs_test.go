package importcli

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/text/encoding/unicode"
)

func writeTestFile(t *testing.T, dir, name string, body []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func utf16Bytes(t *testing.T, s string, e unicode.Endianness, bom unicode.BOMPolicy) []byte {
	t.Helper()
	b, err := unicode.UTF16(e, bom).NewEncoder().Bytes([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A pattern that cmd.exe or PowerShell passes on unexpanded is expanded by
// the CLI, with the platform's separator (a backslash on Windows).
func TestExpandInputs_Patterns(t *testing.T) {
	dir := t.TempDir()
	a := writeTestFile(t, dir, "a.nessus", nil)
	b := writeTestFile(t, dir, "b.nessus", nil)
	writeTestFile(t, dir, "c.xml", nil)
	if err := os.Mkdir(filepath.Join(dir, "d.nessus"), 0o700); err != nil {
		t.Fatal(err)
	}
	lit := writeTestFile(t, dir, "scan[1].xml", nil)

	got, err := expandInputs([]string{filepath.Join(dir, "*.nessus"), a, lit, "-"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{a, b, lit, "-"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	if runtime.GOOS == "windows" && !strings.Contains(got[0], `\`) {
		t.Fatalf("not a Windows path: %q", got[0])
	}
	if _, err := expandInputs([]string{filepath.Join(dir, "*.none")}); err == nil || !strings.Contains(err.Error(), "no file matches") {
		t.Fatalf("no match: %v", err)
	}
}

// Windows paths with a drive letter and backslashes reach the reader
// unchanged and the report is named after the file only.
func TestImport_WindowsPathAndPattern(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "one.xml", []byte(nmapXML))
	r := runWith(t, []string{"--dry-run", filepath.Join(dir, "*.xml")}, "", nil, nil)
	if r.code != ExitOK || !strings.HasPrefix(r.stderr, "one.xml (nmap,") {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	if baseName(`C:\scans\week 45\host.nessus`) != "host.nessus" {
		t.Fatal("baseName keeps the folder")
	}
}

// Exports from Windows tools: UTF-16 with and without a byte order mark, a
// UTF-8 byte order mark and CRLF line ends all read like plain UTF-8.
func TestImport_WindowsEncodings(t *testing.T) {
	crlfXML := strings.ReplaceAll(nmapXML, "\n", "\r\n")
	utf16XML := strings.Replace(crlfXML, `<?xml version="1.0"?>`, `<?xml version="1.0" encoding="UTF-16"?>`, 1)
	lines := "www.example.com\r\napi.example.com\r\n"
	cases := map[string]struct {
		body   []byte
		args   []string
		expect string
	}{
		"xml utf-16le bom":    {utf16Bytes(t, utf16XML, unicode.LittleEndian, unicode.UseBOM), nil, "192.0.2.5:443/tcp"},
		"xml utf-16be bom":    {utf16Bytes(t, utf16XML, unicode.BigEndian, unicode.UseBOM), nil, "192.0.2.5:443/tcp"},
		"xml utf-16le no bom": {utf16Bytes(t, utf16XML, unicode.LittleEndian, unicode.IgnoreBOM), nil, "192.0.2.5:443/tcp"},
		"xml utf-8 bom crlf":  {append([]byte{0xEF, 0xBB, 0xBF}, crlfXML...), nil, "192.0.2.5:443/tcp"},
		"lines utf-16le bom":  {utf16Bytes(t, lines, unicode.LittleEndian, unicode.UseBOM), []string{"--format", "lines", "--as", "domain"}, "api.example.com"},
		"lines utf-8 bom":     {append([]byte{0xEF, 0xBB, 0xBF}, lines...), []string{"--format", "lines", "--as", "domain"}, "www.example.com"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			p := writeTestFile(t, t.TempDir(), "export.out", c.body)
			r := runWith(t, append(append([]string{"--dry-run"}, c.args...), p), "", nil, nil)
			if r.code != ExitOK || !strings.Contains(r.stdout, c.expect) {
				t.Fatalf("exit %d: %s\n%s", r.code, r.stderr, r.stdout)
			}
			if strings.Contains(r.stdout, "\r") || strings.Contains(r.stdout, "\ufeff") {
				t.Fatal("a carriage return or a byte order mark reached the report")
			}
			if !strings.Contains(r.stderr, "0 skipped") {
				t.Fatalf("records skipped: %s", r.stderr)
			}
		})
	}
	// The same through the standard input (a PowerShell pipe).
	r := runWith(t, []string{"--dry-run"}, string(utf16Bytes(t, utf16XML, unicode.LittleEndian, unicode.UseBOM)), nil, nil)
	if r.code != ExitOK {
		t.Fatalf("stdin: exit %d: %s", r.code, r.stderr)
	}
}

// More files than one upload carries are sent in several uploads, each
// with at most MaxInputs files; the exit status is the worst one.
func TestImport_SendsManyFilesInBatches(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < MaxInputs+3; i++ {
		writeTestFile(t, dir, fmt.Sprintf("scan%02d.xml", i), []byte(nmapXML))
	}
	var sizes []int
	calls := 0
	r := runWith(t, []string{"--wait", "0", filepath.Join(dir, "scan*.xml")}, "", map[string]string{EnvAPIKey: testKey, EnvURL: "https://console.example.com"},
		func(_ context.Context, _ *client, f []upload) (*importResponse, error) {
			calls++
			sizes = append(sizes, len(f))
			status := "applied"
			if calls == 2 {
				status = "queued"
			}
			return &importResponse{ReceiptID: fmt.Sprintf("r%d", calls), Status: status}, nil
		})
	if fmt.Sprint(sizes) != fmt.Sprint([]int{MaxInputs, 3}) {
		t.Fatalf("batches %v", sizes)
	}
	if r.code != ExitPending {
		t.Fatalf("exit %d, want %d (one batch still queued): %s", r.code, ExitPending, r.stderr)
	}
	if worse(ExitPending, ExitFail) != ExitFail || worse(ExitFail, ExitOK) != ExitFail || worse(ExitOK, ExitPending) != ExitPending {
		t.Fatal("worse ranks wrongly")
	}
}

// A private CA from --ca-file is trusted in addition to the system roots;
// without it the same server is refused (no skip-verify anywhere).
func TestClient_CAFileAddsToTheSystemRoots(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"receipt_id":"r1","status":"applied","files":[]}`)
	}))
	defer srv.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	caFile := writeTestFile(t, t.TempDir(), "ca.pem", ca)

	send := func(ctx context.Context, c *client, f []upload) (*importResponse, error) { return c.upload(ctx, f) }
	vars := map[string]string{EnvAPIKey: testKey, EnvURL: srv.URL}
	r := runWith(t, []string{"--format", "nmap", "--wait", "0"}, nmapXML, vars, send)
	if r.code != ExitFail || !strings.Contains(r.stderr, "certificate") {
		t.Fatalf("an unknown CA was accepted: exit %d: %s", r.code, r.stderr)
	}
	r = runWith(t, []string{"--format", "nmap", "--wait", "0", "--ca-file", caFile}, nmapXML, vars, send)
	if r.code != ExitOK {
		t.Fatalf("--ca-file: exit %d: %s", r.code, r.stderr)
	}
	vars[EnvCAFile] = caFile
	r = runWith(t, []string{"--format", "nmap", "--wait", "0"}, nmapXML, vars, send)
	if r.code != ExitOK {
		t.Fatalf("%s: exit %d: %s", EnvCAFile, r.code, r.stderr)
	}

	tr, err := transport(caFile)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Proxy == nil {
		t.Fatal("the transport ignores HTTPS_PROXY")
	}
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("verification skipped")
	}
	sys, err := x509.SystemCertPool()
	if err == nil && sys != nil && tr.TLSClientConfig.RootCAs.Equal(x509.NewCertPool()) {
		t.Fatal("the CA file replaced the system roots")
	}
	if _, err := transport(writeTestFile(t, t.TempDir(), "bad.pem", []byte("no pem"))); err == nil {
		t.Fatal("a file without a certificate was accepted")
	}
}

// The command run by "openctem run" never sees the API key, whatever case
// Windows stores its name in.
func TestChildEnv_DropsTheKeyCaseBlind(t *testing.T) {
	got := childEnv([]string{"PATH=x", "OPENCTEM_API_KEY=a", "Openctem_Api_Key=b", "=C:=C:\\", "OPENCTEM_URL=u"})
	if fmt.Sprint(got) != fmt.Sprint([]string{"PATH=x", "=C:=C:\\", "OPENCTEM_URL=u"}) {
		t.Fatalf("env %q", got)
	}
}

func TestDecodeText_LeavesOtherInputAlone(t *testing.T) {
	for _, in := range []string{"", "a", "{\"x\":1}", "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><a/>"} {
		r, err := decodeText(strings.NewReader(in))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(r)
		if !bytes.Equal(b, []byte(in)) {
			t.Fatalf("%q became %q", in, b)
		}
	}
}
