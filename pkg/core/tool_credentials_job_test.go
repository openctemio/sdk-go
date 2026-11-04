package core

import (
	"context"
	"fmt"
	"testing"
)

type fakeToolCreds struct{ cmd, tool string }

func (f *fakeToolCreds) ToolCredentials(_ context.Context, cmdID, tool string) (*ToolCredentialSet, error) {
	f.cmd, f.tool = cmdID, tool
	return &ToolCredentialSet{Values: map[string]string{"k": "v"}}, nil
}

func TestJobToolCredentialsBoundToTheCommand(t *testing.T) {
	e := &DefaultCommandExecutor{}
	if ToolCredentialsFrom(e.withJobToolCredentials(context.Background(), "c1")) != nil {
		t.Fatal("a fetch without a wired source")
	}
	f := &fakeToolCreds{}
	e.SetToolCredentials(f)
	if ToolCredentialsFrom(e.withJobToolCredentials(context.Background(), "")) != nil {
		t.Fatal("a fetch without a command")
	}
	fetch := ToolCredentialsFrom(e.withJobToolCredentials(context.Background(), "c1"))
	if fetch == nil {
		t.Fatal("no fetch on the job context")
	}
	if _, err := fetch(context.Background(), "subfinder"); err != nil || f.cmd != "c1" || f.tool != "subfinder" {
		t.Fatalf("fetch asked %q/%q: %v", f.cmd, f.tool, err)
	}
	e.SetToolCredentials(nil)
	if ToolCredentialsFrom(e.withJobToolCredentials(context.Background(), "c1")) != nil {
		t.Fatal("fetch after unwiring")
	}
}

func TestMergeToolCredentials(t *testing.T) {
	local := map[string]string{"a": "la", "b": "lb", "e": ""}
	cases := []struct {
		job  *ToolCredentialSet
		want string
	}{
		{nil, "map[a:la b:lb e:]"},
		{&ToolCredentialSet{Values: map[string]string{"a": "oa", "c": ""}, LocalFallback: true}, "map[a:oa b:lb]"},
		{&ToolCredentialSet{Values: map[string]string{"a": "oa"}}, "map[a:oa]"},
		{&ToolCredentialSet{}, "map[]"},
	}
	for i, c := range cases {
		if got := fmt.Sprint(MergeToolCredentials(c.job, local)); got != c.want {
			t.Errorf("case %d: %s, want %s", i, got, c.want)
		}
	}
}
