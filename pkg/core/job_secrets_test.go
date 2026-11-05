package core

import (
	"context"
	"encoding/json"
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
// skip; an invalid list refuses the job; an unverified payload's list is
// ignored (no platform values), never a refusal.
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
	js, err = JobSecretsFor(&Command{ID: "c1", Payload: secretsPayload(t, unknownRef(true))}, false, nil)
	if err != nil {
		t.Fatalf("unverified: %v", err)
	}
	if _, ok := js.Set(); ok {
		t.Fatal("an unverified payload's secret list was used")
	}
	if js, err := JobSecretsFor(verified(json.RawMessage(`{"scanner":"x"}`)), false, nil); err != nil {
		t.Fatal(err)
	} else if _, ok := js.Set(); ok {
		t.Fatal("a job without a list has one")
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
