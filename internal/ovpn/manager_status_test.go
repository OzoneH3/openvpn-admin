package ovpn

import "testing"

func TestPortListedUDP(t *testing.T) {
	data := []byte("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n  42: 00000000:2E94 00000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 1\n")
	if !portListed(data, 11924, false) {
		t.Fatal("expected UDP port 11924 to be detected")
	}
	if portListed(data, 1194, false) {
		t.Fatal("unexpected match for UDP port 1194")
	}
}

func TestPortListedTCPRequiresListenState(t *testing.T) {
	listen := []byte("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:04AA 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1\n")
	connected := []byte("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:04AA 0100007F:1234 01 00000000:00000000 00:00000000 00000000 0 0 1\n")
	if !portListed(listen, 1194, true) {
		t.Fatal("expected TCP LISTEN socket to be detected")
	}
	if portListed(connected, 1194, true) {
		t.Fatal("established TCP socket must not count as a listener")
	}
}
