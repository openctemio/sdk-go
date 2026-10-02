package connectors

import "testing"

func TestSanitizeLogValue(t *testing.T) {
	cases := map[string]string{
		"/repos/a/b":               "/repos/a/b",
		"/x\nFAKE LINE":            "/xFAKE LINE",
		"/x\r\n[github] GET /fake": "/x[github] GET /fake",
		"":                         "",
	}
	for in, want := range cases {
		if got := sanitizeLogValue(in); got != want {
			t.Errorf("sanitizeLogValue(%q) = %q, want %q", in, got, want)
		}
	}
}
