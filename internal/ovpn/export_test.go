package ovpn

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExportClientRejectsInvalidInputs(t *testing.T) {
	m := NewManager(t.TempDir(), t.TempDir(), "", "", "")

	if _, err := m.ExportClient(context.Background(), "../root", "p12"); err == nil {
		t.Fatal("expected invalid CN to be rejected")
	}
	if _, err := m.ExportClient(context.Background(), "alice", "../../key"); err == nil {
		t.Fatal("expected unsupported format to be rejected")
	}
}

func TestExportClientPKCSFormats(t *testing.T) {
	tests := []struct {
		format   string
		ext      string
		relPath  string
		contents string
	}{
		{"p12", ".p12", filepath.Join("pki", "private", "alice.p12"), "p12-data"},
		{"p7", ".p7b", filepath.Join("pki", "issued", "alice.p7b"), "p7-data"},
		{"p8", ".p8", filepath.Join("pki", "private", "alice.p8"), "p8-data"},
		{"p1", ".p1", filepath.Join("pki", "private", "alice.p1"), "p1-data"},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			easyRSA := t.TempDir()
			installFakeEasyRSA(t, easyRSA)
			m := NewManager(t.TempDir(), easyRSA, "", "", "")

			artifact, err := m.ExportClient(context.Background(), "alice", tt.format)
			if err != nil {
				t.Fatalf("ExportClient: %v", err)
			}
			if artifact.Filename != "alice"+tt.ext {
				t.Fatalf("filename = %q, want %q", artifact.Filename, "alice"+tt.ext)
			}
			if string(artifact.Data) != tt.contents {
				t.Fatalf("data = %q, want %q", artifact.Data, tt.contents)
			}
			if _, err := os.Stat(filepath.Join(easyRSA, tt.relPath)); !os.IsNotExist(err) {
				t.Fatalf("generated artifact was not cleaned up: %v", err)
			}

			args, err := os.ReadFile(filepath.Join(easyRSA, "args.txt"))
			if err != nil {
				t.Fatalf("read args: %v", err)
			}
			got := string(args)
			for _, want := range []string{"--batch", "--nopass", "--noinline", "alice"} {
				if !strings.Contains(got, want) {
					t.Fatalf("EasyRSA args %q missing %q", got, want)
				}
			}
		})
	}
}

func TestExportClientInline(t *testing.T) {
	easyRSA := t.TempDir()
	installFakeEasyRSA(t, easyRSA)
	m := NewManager(t.TempDir(), easyRSA, "", "", "")

	artifact, err := m.ExportClient(context.Background(), "alice", "inline")
	if err != nil {
		t.Fatalf("ExportClient inline: %v", err)
	}
	if artifact.Filename != "alice.inline" {
		t.Fatalf("filename = %q", artifact.Filename)
	}
	if string(artifact.Data) != "inline-data" {
		t.Fatalf("data = %q", artifact.Data)
	}
	path := filepath.Join(easyRSA, "pki", "inline", "private", "alice.inline")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("generated inline artifact was not cleaned up: %v", err)
	}
}

func installFakeEasyRSA(t *testing.T, dir string) {
	t.Helper()
	script := `#!/bin/sh
set -eu
printf '%s\n' "$@" > args.txt
cmd=""
for arg in "$@"; do
  case "$arg" in
    export-p12|export-p7|export-p8|export-p1|inline) cmd="$arg" ;;
  esac
done
case "$cmd" in
  export-p12)
    mkdir -p pki/private
    printf 'p12-data' > pki/private/alice.p12
    ;;
  export-p7)
    mkdir -p pki/issued
    printf 'p7-data' > pki/issued/alice.p7b
    ;;
  export-p8)
    mkdir -p pki/private
    printf 'p8-data' > pki/private/alice.p8
    ;;
  export-p1)
    mkdir -p pki/private
    printf 'p1-data' > pki/private/alice.p1
    ;;
  inline)
    mkdir -p pki/inline/private
    printf 'inline-data' > pki/inline/private/alice.inline
    ;;
  *) exit 9 ;;
esac
`
	path := filepath.Join(dir, "easyrsa")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake easyrsa: %v", err)
	}
}
