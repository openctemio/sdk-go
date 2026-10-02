package katana

import (
	"os"
	"testing"

	"github.com/openctemio/sdk-go/pkg/scanners/recon/internal/flagcheck"
)

// Real katana 1.7.0 -jsonl output: a local site with one link, then a
// refused URL. The request is an object; decoding it into a string made
// every line a "plain URL" holding the whole JSON text.
func TestParseOutput_Real(t *testing.T) {
	data, err := os.ReadFile(flagcheck.Testdata("katana-1.7.0.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	urls, err := NewScanner().parseOutput(data)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, u := range urls {
		got[u.URL] = u.StatusCode
	}
	want := map[string]int{"http://127.0.0.1:18777": 200, "http://127.0.0.1:18777/a.html": 200}
	if len(got) != len(want) {
		t.Fatalf("urls = %v, want %v", got, want)
	}
	for u, code := range want {
		if got[u] != code {
			t.Errorf("%s: status %d, want %d (all %v)", u, got[u], code, got)
		}
	}
}
