package importcli

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeAssets serves two pages of assets and records the queries.
func fakeAssets(t *testing.T, queries *[]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testKey || r.URL.Path != "/api/v1/assets" {
			http.Error(w, `{"message":"no"}`, http.StatusUnauthorized)
			return
		}
		*queries = append(*queries, r.URL.RawQuery)
		switch r.URL.Query().Get("page") {
		case "1":
			_, _ = w.Write([]byte(`{"data":[{"type":"domain","name":"example.com"},{"type":"subdomain","name":"www.example.com"},{"type":"subdomain","name":"bad name\u001b[2J"}],"total_pages":2}`))
		default:
			_, _ = w.Write([]byte(`{"data":[{"type":"subdomain","name":"www.example.com"},{"type":"subdomain","name":"api.example.com"}],"total_pages":2}`))
		}
	}))
}

func TestTargetsExport_InScopeByDefaultPagedAndDeduplicated(t *testing.T) {
	var queries []string
	srv := fakeAssets(t, &queries)
	defer srv.Close()
	var out, errb bytes.Buffer
	vars := map[string]string{EnvURL: srv.URL, EnvAPIKey: testKey}
	code := TargetsMain([]string{"export", "--type", "domain", "--tag", "prod"}, &out, &errb, func(k string) string { return vars[k] })
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if got := out.String(); got != "example.com\nwww.example.com\napi.example.com\n" {
		t.Fatalf("export = %q", got)
	}
	if len(queries) != 2 || !strings.Contains(queries[0], "scope_status=in_scope") || !strings.Contains(queries[0], "types=domain%2Csubdomain") || !strings.Contains(queries[0], "tags=prod") {
		t.Fatalf("queries = %v", queries)
	}
	for _, bad := range [][]string{{"export"}, {"export", "--type", "planet"}, {"export", "--type", "ip", "--scope", "everything"}, {"list"}} {
		if c := TargetsMain(bad, &out, &errb, func(k string) string { return vars[k] }); c == ExitOK {
			t.Fatalf("%v accepted", bad)
		}
	}
}

func TestRun_ExportsRunsAndImportsWithoutTheKey(t *testing.T) {
	var queries []string
	srv := fakeAssets(t, &queries)
	defer srv.Close()
	t.Setenv(EnvAPIKey, testKey)
	vars := map[string]string{EnvURL: srv.URL, EnvAPIKey: testKey}
	getenv := func(k string) string { return vars[k] }
	var out, errb bytes.Buffer
	// The command copies the targets to its output and adds a name made of
	// the key it can see ("none" when it cannot).
	code := RunMain([]string{"--type", "domain", "--format", "lines", "--as", "domain", "--tool", "copy", "--dry-run", "--",
		"sh", "-c", `cat "$1" > "$2"; echo "${OPENCTEM_API_KEY:-none}.example.org" >> "$2"`, "sh", "{targets_file}", "{output_file}"},
		&out, &errb, getenv)
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	for _, want := range []string{"api.example.com", "none.example.org", `"name": "copy"`} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("report lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String()+errb.String(), testKey) {
		t.Fatal("the command saw the API key")
	}
	if c := RunMain([]string{"--type", "domain"}, &out, &errb, getenv); c != ExitUsage {
		t.Fatalf("no command: exit %d", c)
	}
}
