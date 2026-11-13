package cloudflare

import (
	"testing"
	"time"
)

func TestSplitWindow(t *testing.T) {
	s := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e := s.Add(time.Hour)
	if got := splitWindow(s, e, 0); len(got) != 1 {
		t.Fatalf("no max: %v", got)
	}
	got := splitWindow(s, e, 25*time.Minute)
	if len(got) != 3 || !got[2][1].Equal(e) || !got[1][0].Equal(s.Add(25*time.Minute)) {
		t.Fatalf("unexpected split: %v", got)
	}
}
