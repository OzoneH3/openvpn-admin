package ovpn

import (
	"bufio"
	"context"
	"os/exec"
	"strings"
	"time"
)

// LogEntry is a structured journal line for the Logs page.
type LogEntry struct {
	Timestamp *time.Time `json:"ts,omitempty"`
	Level     string     `json:"level"` // info | warn | err | ok
	Message   string     `json:"msg"`
}

// TailJournal returns the last n entries from the openvpn-server unit
// journal, classified into the SPA's level buckets.
func (m *Manager) TailJournal(ctx context.Context, n int) ([]LogEntry, error) {
	if n <= 0 {
		n = 200
	}
	cmd := exec.CommandContext(ctx, "journalctl",
		"-u", m.ServiceUnit,
		"-n", itoa(n),
		"--no-pager",
		"--output=short-iso",
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var out []LogEntry
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "-- ") {
			continue
		}
		out = append(out, parseJournalLine(line))
	}
	_ = cmd.Wait()
	return out, sc.Err()
}

// parseJournalLine splits a journalctl short-iso line into ts / level / msg.
// systemd versions differ slightly in whether fractional seconds are emitted
// and whether the timezone offset contains a colon, so accept the common
// variants rather than turning a parse failure into Go's year-1 zero time.
func parseJournalLine(line string) LogEntry {
	e := LogEntry{Level: "info", Message: line}
	parts := strings.SplitN(line, " ", 4)
	if len(parts) < 4 {
		return e
	}
	if t, ok := parseJournalTimestamp(parts[0]); ok {
		e.Timestamp = &t
	}
	e.Message = parts[3]
	low := strings.ToLower(e.Message)
	switch {
	case strings.Contains(low, "auth_failed"), strings.Contains(low, "tls error"),
		strings.Contains(low, "verify error"), strings.Contains(low, "fatal"),
		strings.Contains(low, "error:"):
		e.Level = "err"
	case strings.Contains(low, "warning"), strings.Contains(low, "expir"):
		e.Level = "warn"
	case strings.Contains(low, "peer connection initiated"),
		strings.Contains(low, "tls: soft reset"),
		strings.Contains(low, "initialization sequence completed"):
		e.Level = "ok"
	}
	return e
}

func parseJournalTimestamp(value string) (time.Time, bool) {
	layouts := []string{
		"2006-01-02T15:04:05-0700",
		"2006-01-02T15:04:05.999999-0700",
		time.RFC3339,
		time.RFC3339Nano,
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, value); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func itoa(n int) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	buf := [20]byte{}
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = digits[n%10]
		n /= 10
	}
	return string(buf[i:])
}
