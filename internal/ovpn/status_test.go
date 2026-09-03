package ovpn

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadSessionsLegacyStatusV1(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "openvpn.status")
	data := `OpenVPN CLIENT LIST
Updated,2026-09-03 15:32:28
Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
pi3_camp_ap,udp4:195.29.81.234:43791,11671075,190039646,2026-09-03 15:15:00
ROUTING TABLE
Virtual Address,Common Name,Real Address,Last Ref
10.8.0.5,pi3_camp_ap,udp4:195.29.81.234:43791,2026-09-03 15:32:27
GLOBAL STATS
Max bcast/mcast queue length,1
END
`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	sessions, err := ReadSessions(path)
	if err != nil {
		t.Fatalf("ReadSessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("got %d sessions, want 1", len(sessions))
	}
	s := sessions[0]
	if s.CommonName != "pi3_camp_ap" {
		t.Fatalf("CommonName = %q", s.CommonName)
	}
	if s.RealIP != "udp4:195.29.81.234:43791" {
		t.Fatalf("RealIP = %q", s.RealIP)
	}
	if s.VirtualIP != "10.8.0.5" {
		t.Fatalf("VirtualIP = %q", s.VirtualIP)
	}
	if s.BytesIn != 11671075 || s.BytesOut != 190039646 {
		t.Fatalf("bytes = %d/%d", s.BytesIn, s.BytesOut)
	}
	if s.ConnectedAt.IsZero() {
		t.Fatal("ConnectedAt is zero")
	}
}
