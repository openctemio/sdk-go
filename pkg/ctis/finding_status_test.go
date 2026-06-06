package ctis

import "testing"

// TestFindingStatus_AllAndIsValid locks the FindingStatus enum so this copy
// cannot silently drift from the standalone ctis module again (the cause of the
// 2026-06 drift where "suppressed" + these helpers were missing here).
func TestFindingStatus_AllAndIsValid(t *testing.T) {
	all := AllFindingStatuses()
	if len(all) != 6 {
		t.Fatalf("expected 6 finding statuses, got %d: %v", len(all), all)
	}
	want := map[FindingStatus]bool{
		FindingStatusOpen:          true,
		FindingStatusResolved:      true,
		FindingStatusSuppressed:    true,
		FindingStatusFalsePositive: true,
		FindingStatusAcceptedRisk:  true,
		FindingStatusInProgress:    true,
	}
	for _, s := range all {
		if !want[s] {
			t.Errorf("unexpected status in AllFindingStatuses: %q", s)
		}
		if !s.IsValid() {
			t.Errorf("status %q from AllFindingStatuses must be valid", s)
		}
		delete(want, s)
	}
	if len(want) != 0 {
		t.Errorf("AllFindingStatuses is missing statuses: %v", want)
	}
	if FindingStatus("bogus").IsValid() {
		t.Error("an unknown status must not be valid")
	}
}
