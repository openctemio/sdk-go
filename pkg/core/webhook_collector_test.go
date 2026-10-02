package core

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func postWebhook(c *WebhookCollector, body string, header map[string]string) int {
	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(body))
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	c.handleWebhook(rec, req)
	return rec.Code
}

// A configured Secret must be required: before, the field was accepted and
// ignored, so anyone who could reach the port could inject reports.
func TestWebhookCollector_SecretRequired(t *testing.T) {
	c := NewWebhookCollector(&WebhookCollectorConfig{Secret: "s3cret"})
	cases := []struct {
		name   string
		header map[string]string
		want   int
	}{
		{"no credential", nil, http.StatusUnauthorized},
		{"wrong bearer", map[string]string{"Authorization": "Bearer nope"}, http.StatusUnauthorized},
		{"wrong header", map[string]string{"X-Webhook-Secret": "nope"}, http.StatusUnauthorized},
		{"bearer", map[string]string{"Authorization": "Bearer s3cret"}, http.StatusAccepted},
		{"header", map[string]string{"X-Webhook-Secret": "s3cret"}, http.StatusAccepted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := postWebhook(c, `{}`, tc.header); got != tc.want {
				t.Fatalf("status = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestWebhookCollector_NoSecretAcceptsAnonymous(t *testing.T) {
	c := NewWebhookCollector(&WebhookCollectorConfig{})
	if got := postWebhook(c, `{}`, nil); got != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", got, http.StatusAccepted)
	}
}

// The body is bounded: an unbounded io.ReadAll let any client exhaust memory.
func TestWebhookCollector_BodyBounded(t *testing.T) {
	c := NewWebhookCollector(&WebhookCollectorConfig{MaxBodyBytes: 16})
	if got := postWebhook(c, strings.Repeat("x", 17), nil); got != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", got, http.StatusRequestEntityTooLarge)
	}
	if got := postWebhook(c, strings.Repeat("x", 16), nil); got != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", got, http.StatusAccepted)
	}
}
