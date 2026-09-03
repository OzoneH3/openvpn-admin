package ovpn

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Session is one connected client as reported in OpenVPN's status.log.
type Session struct {
	CommonName  string    `json:"user"`
	RealIP      string    `json:"real_ip"`
	VirtualIP   string    `json:"virtual_ip"`
	BytesIn     int64     `json:"bytes_in"`
	BytesOut    int64     `json:"bytes_out"`
	ConnectedAt time.Time `json:"connected_at"`
	Cipher      string    `json:"cipher,omitempty"`
	PeerID      string    `json:"peer_id,omitempty"`
}

// ReadSessions parses OpenVPN status files in both the legacy human-readable
// v1 layout and the machine-readable status-version 2 CLIENT_LIST layout.
func ReadSessions(statusPath string) ([]Session, error) {
	f, err := os.Open(statusPath)
	if err != nil {
		return nil, fmt.Errorf("open status.log: %w", err)
	}
	defer f.Close()

	var sessions []Session
	var legacyByCN = map[string]*Session{}
	legacySection := ""

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		// status-version 2/3 machine-readable rows.
		if strings.HasPrefix(line, "CLIENT_LIST,") {
			parts := strings.Split(line, ",")
			if len(parts) < 9 {
				continue
			}
			s := Session{
				CommonName: parts[1],
				RealIP:     parts[2],
				VirtualIP:  parts[3],
			}
			s.BytesIn, _ = strconv.ParseInt(parts[5], 10, 64)
			s.BytesOut, _ = strconv.ParseInt(parts[6], 10, 64)
			if ts, err := strconv.ParseInt(parts[8], 10, 64); err == nil {
				s.ConnectedAt = time.Unix(ts, 0)
			}
			if len(parts) > 11 {
				s.PeerID = parts[11]
			}
			if len(parts) > 12 {
				s.Cipher = parts[12]
			}
			sessions = append(sessions, s)
			continue
		}

		// Legacy status-version 1 human-readable layout.
		switch line {
		case "OpenVPN CLIENT LIST":
			legacySection = "clients"
			continue
		case "ROUTING TABLE":
			legacySection = "routes"
			continue
		case "GLOBAL STATS", "END":
			legacySection = ""
			continue
		}
		if strings.HasPrefix(line, "Updated,") ||
			strings.HasPrefix(line, "Common Name,") ||
			strings.HasPrefix(line, "Virtual Address,") ||
			strings.HasPrefix(line, "Max bcast/mcast queue length,") {
			continue
		}

		parts := strings.Split(line, ",")
		switch legacySection {
		case "clients":
			if len(parts) < 5 {
				continue
			}
			s := &Session{CommonName: parts[0], RealIP: parts[1]}
			s.BytesIn, _ = strconv.ParseInt(parts[2], 10, 64)
			s.BytesOut, _ = strconv.ParseInt(parts[3], 10, 64)
			if t, err := time.Parse("2006-01-02 15:04:05", parts[4]); err == nil {
				s.ConnectedAt = t
			}
			legacyByCN[s.CommonName] = s
		case "routes":
			if len(parts) < 2 {
				continue
			}
			if s := legacyByCN[parts[1]]; s != nil {
				s.VirtualIP = parts[0]
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	if len(sessions) == 0 && len(legacyByCN) > 0 {
		sessions = make([]Session, 0, len(legacyByCN))
		for _, s := range legacyByCN {
			sessions = append(sessions, *s)
		}
	}
	return sessions, nil
}
