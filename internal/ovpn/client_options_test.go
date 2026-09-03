package ovpn

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestAddClientWithOptionsRejectsInvalidValidity(t *testing.T) {
	m := NewManager(t.TempDir(), t.TempDir(), t.TempDir(), "", "")
	for _, days := range []int{-1, 3651} {
		_, err := m.AddClientWithOptions(context.Background(), "test", ClientCreateOptions{CertDays: days})
		if err == nil || !strings.Contains(err.Error(), "certificate validity") {
			t.Fatalf("days=%d: expected validity error, got %v", days, err)
		}
	}
}

func TestWritePassphraseFileIsPrivateAndTemporary(t *testing.T) {
	path, err := writePassphraseFile("client-secret")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o, want 600", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "client-secret\n" {
		t.Fatalf("unexpected passphrase file contents")
	}
}
