package ovpn

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCAArgsUsePassphraseFile(t *testing.T) {
	m := NewManager("", "", "", "", "")
	m.CAPasswordFile = "/run/secrets/ca-pass"
	args := m.caArgs("build-client-full", "alice", "nopass")
	got := strings.Join(args, " ")
	if !strings.Contains(got, "--passin=file:/run/secrets/ca-pass") {
		t.Fatalf("args missing CA passin file: %q", got)
	}
	if !strings.HasSuffix(got, "build-client-full alice nopass") {
		t.Fatalf("client nopass command lost: %q", got)
	}
}

func TestBuildOVPNSupportsDottedCNAndCustomPaths(t *testing.T) {
	root := t.TempDir()
	easy := filepath.Join(root, "ca")
	pki := filepath.Join(easy, "pki")
	for _, dir := range []string{filepath.Join(pki, "issued"), filepath.Join(pki, "private")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(pki, "ca.crt"), "CA\n")
	write(filepath.Join(pki, "issued", "satori.cx.crt"), "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----\n")
	write(filepath.Join(pki, "private", "satori.cx.key"), "KEY\n")
	template := filepath.Join(root, "client-template.txt")
	tlsCrypt := filepath.Join(root, "server-tls-crypt.key")
	write(template, "client\nremote vpn.example 11922 udp\n")
	write(tlsCrypt, "TLSCRYPT\n")

	m := NewManager(root, easy, filepath.Join(root, "clients"), "", "")
	m.ClientTemplatePath = template
	m.TLSCryptKeyPath = tlsCrypt
	m.TLSAuthKeyPath = filepath.Join(root, "missing-tls-auth.key")

	bundle, err := m.BuildOVPN("satori.cx")
	if err != nil {
		t.Fatalf("BuildOVPN dotted CN: %v", err)
	}
	got := string(bundle)
	for _, want := range []string{"remote vpn.example 11922 udp", "<ca>\nCA", "<cert>\n-----BEGIN CERTIFICATE-----", "<key>\nKEY", "<tls-crypt>\nTLSCRYPT"} {
		if !strings.Contains(got, want) {
			t.Fatalf("bundle missing %q:\n%s", want, got)
		}
	}
}

func TestCNValidationStillRejectsPaths(t *testing.T) {
	for _, cn := range []string{"../root", "alice/bob", "alice bob", "alice;id"} {
		if validCN.MatchString(cn) {
			t.Fatalf("unsafe CN accepted: %q", cn)
		}
	}
}
