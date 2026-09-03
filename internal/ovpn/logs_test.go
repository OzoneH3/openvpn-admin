package ovpn

import (
	"testing"
	"time"
)

func TestParseJournalTimestampVariants(t *testing.T) {
	tests := []string{
		"2026-09-03T21:20:33+0200",
		"2026-09-03T21:20:33.123456+0200",
		"2026-09-03T21:20:33+02:00",
		"2026-09-03T21:20:33.123456789+02:00",
	}
	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			got, ok := parseJournalTimestamp(input)
			if !ok {
				t.Fatalf("parseJournalTimestamp(%q) failed", input)
			}
			if got.Year() != 2026 || got.Month() != time.September || got.Day() != 3 {
				t.Fatalf("unexpected timestamp: %v", got)
			}
		})
	}
}

func TestParseJournalLineInvalidTimestampOmitsZeroTime(t *testing.T) {
	entry := parseJournalLine("not-a-date host openvpn[123]: Options error: broken config")
	if entry.Timestamp != nil {
		t.Fatalf("expected nil timestamp, got %v", entry.Timestamp)
	}
	if entry.Level != "err" {
		t.Fatalf("expected err level, got %q", entry.Level)
	}
}

func TestParseJournalLineValidTimestamp(t *testing.T) {
	entry := parseJournalLine("2026-09-03T21:20:33.123456+0200 host openvpn[123]: Initialization Sequence Completed")
	if entry.Timestamp == nil {
		t.Fatal("expected parsed timestamp")
	}
	if entry.Timestamp.Year() != 2026 {
		t.Fatalf("unexpected timestamp: %v", entry.Timestamp)
	}
	if entry.Level != "ok" {
		t.Fatalf("expected ok level, got %q", entry.Level)
	}
}
