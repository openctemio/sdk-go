package core

import "testing"

func TestContentVersionHint(t *testing.T) {
	for body, want := range map[string]string{
		`{"content_version":"\"3f9a1c\""}`:   `"3f9a1c"`,
		`{"content_version":"abc123"}`:       "abc123",
		`{"content_version":""}`:             "",
		`{"content_version":"has space"}`:    "",
		`{"content_version":"evil\nheader"}`: "",
		`{"pending_jobs":1}`:                 "",
	} {
		if got := ParseHeartbeatHints([]byte(body)).ContentVersion; got != want {
			t.Errorf("%s: ContentVersion = %q, want %q", body, got, want)
		}
	}
	long := make([]byte, maxHintContentVersionLen+1)
	for i := range long {
		long[i] = 'a'
	}
	if ParseHeartbeatHints([]byte(`{"content_version":"`+string(long)+`"}`)).ContentVersion != "" {
		t.Error("an over-long content version was accepted")
	}
}

// A content version that differs from the last one tells the sensor to
// refresh its content, once per change.
func TestDoorbellContentHandlerRunsOncePerChange(t *testing.T) {
	d := NewDoorbell(&DoorbellConfig{})
	var got []string
	d.SetContentHandler(func(v string) { got = append(got, v) })
	for _, v := range []string{"a1", "a1", "", "b2", "b2", "a1"} {
		d.Handle(&HeartbeatHints{Present: true, ContentVersion: v})
	}
	if want := []string{"a1", "b2", "a1"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("handler saw %v, want %v", got, want)
	}
}
