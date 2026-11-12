package core

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/contract/secretref"
)

func secretsPayload(t *testing.T, refs ...map[string]any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(map[string]any{"scanner": "x", secretref.PayloadField: map[string]any{"v": 1, "local": "allow", "refs": refs}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func unknownRef(required bool) map[string]any {
	return map[string]any{"id": "x1", "kind": "client_cert", "class": "target", "ref": "cred-1", "slot": "client_cert",
		"audience": []string{"targets"}, "consumer": "tool", "required": required, "local": "never"}
}

// SECURITY: the secret list comes only from a verified job. A required ref
// of a kind this sensor does not know refuses the job
// (secret_kind_unsupported); an optional one is kept for its consumers to
// skip; an invalid list refuses the job; an unverified payload's list
// gives no platform values (TestJobSecretsFor_Unverified).
func TestJobSecretsFor(t *testing.T) {
	verified := func(p json.RawMessage) *Command { return &Command{ID: "c1", Payload: p, jobVerified: true} }
	_, err := JobSecretsFor(verified(secretsPayload(t, unknownRef(true))), false, nil)
	if r := RefusalOf(err); r == nil || r.Rule != secretref.RefusalKindUnsupported || r.Layer != RefusalLayerBuiltin {
		t.Fatalf("required unknown kind: %v", err)
	}
	js, err := JobSecretsFor(verified(secretsPayload(t, unknownRef(false))), false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if set, ok := js.Set(); !ok || len(set.Refs) != 1 {
		t.Fatalf("optional unknown kind: %+v", set)
	}
	bad := unknownRef(false)
	bad["local"] = "sometimes"
	if _, err := JobSecretsFor(verified(secretsPayload(t, bad)), false, nil); RefusalOf(err) == nil || RefusalOf(err).Rule != RefusalRuleSecretsInvalid {
		t.Fatalf("invalid list: %v", err)
	}
	if js, err := JobSecretsFor(verified(json.RawMessage(`{"scanner":"x"}`)), false, nil); err != nil {
		t.Fatal(err)
	} else if _, ok := js.Set(); ok {
		t.Fatal("a job without a list has one")
	}
}

// SECURITY: an unverified job (no job signer pinned, or an unsigned job)
// never gets platform values. One whose list requires a secret is refused
// with secrets_unverified and a fix in the detail, instead of running
// without its credentials (a proxy pool job failing later with a vague
// reason, an authenticated scan running unauthenticated); optional refs
// are left out and counted so the job log says so. An unreadable list on
// an unverified job is not a refusal: nothing of it is used.
func TestJobSecretsFor_Unverified(t *testing.T) {
	unverified := func(p json.RawMessage) *Command { return &Command{ID: "c1", Payload: p} }
	js, err := JobSecretsFor(unverified(secretsPayload(t, unknownRef(true))), false, nil)
	r := RefusalOf(err)
	if r == nil || r.Rule != RefusalRuleSecretsUnverified || r.Layer != RefusalLayerBuiltin {
		t.Fatalf("required secret on an unverified job: err=%v", err)
	}
	if !strings.Contains(r.Detail, "SENSOR_JOB_SIGNING_ROOT") || !strings.Contains(r.Detail, "x1") {
		t.Fatalf("the refusal names neither the secret nor the fix: %q", r.Detail)
	}
	if js == nil {
		t.Fatal("nil secrets")
	} else if _, ok := js.Set(); ok {
		t.Fatal("an unverified payload's secret list was used")
	}

	second := unknownRef(false)
	second["id"], second["ref"], second["slot"] = "x2", "cred-2", "client_cert_2"
	js, err = JobSecretsFor(unverified(secretsPayload(t, unknownRef(false), second)), false, nil)
	if err != nil {
		t.Fatalf("optional secrets on an unverified job: %v", err)
	}
	if _, ok := js.Set(); ok {
		t.Fatal("an unverified payload's secret list was used")
	}
	if js.IgnoredOptional() != 2 {
		t.Fatalf("IgnoredOptional = %d, want 2", js.IgnoredOptional())
	}

	bad := unknownRef(true)
	bad["local"] = "sometimes"
	if js, err := JobSecretsFor(unverified(secretsPayload(t, bad)), false, nil); err != nil || js.IgnoredOptional() != 0 {
		t.Fatalf("unreadable list on an unverified job: %v", err)
	}
	if js, err := JobSecretsFor(unverified(json.RawMessage(`{"scanner":"x"}`)), false, nil); err != nil || js.IgnoredOptional() != 0 {
		t.Fatalf("no list: %v", err)
	}
}

// SECURITY: a shared identity forces "never" for every slot, whatever the
// signed list says.
func TestLocalSecretPolicy(t *testing.T) {
	set := &secretref.Set{V: 1, Local: secretref.LocalAllow, Refs: []secretref.Ref{
		{ID: "k1", Kind: secretref.KindProviderKey, Class: secretref.ClassProvider, Ref: "shodan", Slot: "shodan",
			Audience: []string{"provider:shodan"}, Consumer: secretref.ConsumerTool, Local: secretref.LocalOnly}}}
	org := NewJobSecrets("c1", set, false, nil)
	if org.LocalPolicy("shodan") != secretref.LocalOnly || org.LocalPolicy("other") != secretref.LocalAllow {
		t.Fatal("org policies")
	}
	shared := NewJobSecrets("c1", set, true, nil)
	if shared.LocalPolicy("shodan") != secretref.LocalNever || shared.LocalPolicy("other") != secretref.LocalNever {
		t.Fatal("a shared identity used the job's policy")
	}
	if LocalSecretPolicy(org, "other", true) != secretref.LocalNever || LocalSecretPolicy(nil, "x", false) != secretref.LocalAllow {
		t.Fatal("host view")
	}
	// No fetcher or no list: no platform values.
	if _, err := NewJobSecrets("c1", nil, false, &fakeSecrets{}).Fetch(context.Background(), "t", []string{"k1"}); err == nil {
		t.Fatal("fetched without a list")
	}
	if _, err := org.Fetch(context.Background(), "t", []string{"k1"}); err == nil {
		t.Fatal("fetched without a fetcher")
	}
	if _, err := NewJobSecrets("c1", set, false, &fakeSecrets{}).Fetch(context.Background(), "t", []string{"zz"}); err == nil {
		t.Fatal("fetched a ref the job does not list")
	}
}
