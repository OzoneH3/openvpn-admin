package ovpn

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Manager wires together the on-disk OpenVPN/easyrsa state with shell commands.
type Manager struct {
	OpenVPNDir         string
	EasyRSADir         string
	ClientsDir         string
	StatusPath         string
	ServiceUnit        string
	ListenPort         int
	ListenProto        string
	ClientTemplatePath string
	TLSCryptKeyPath    string
	TLSAuthKeyPath     string
	CAPasswordFile     string
}

// ClientCreateOptions controls certificate validity and private-key protection.
type ClientCreateOptions struct {
	CertDays int
	Password string
}

const (
	defaultClientCertDays = 3650
	minClientCertDays     = 1
	maxClientCertDays     = 3650
)

// NewManager applies defaults that match the upstream openvpn-install.sh.
func NewManager(openVPNDir, easyRSADir, clientsDir, statusPath, unit string) *Manager {
	if openVPNDir == "" {
		openVPNDir = "/etc/openvpn"
	}
	if easyRSADir == "" {
		easyRSADir = filepath.Join(openVPNDir, "easy-rsa")
	}
	if clientsDir == "" {
		clientsDir = filepath.Join(openVPNDir, "clients")
	}
	if statusPath == "" {
		statusPath = "/var/log/openvpn/status.log"
	}
	if unit == "" {
		unit = "openvpn-server@server.service"
	}
	return &Manager{
		OpenVPNDir:         openVPNDir,
		EasyRSADir:         easyRSADir,
		ClientsDir:         clientsDir,
		StatusPath:         statusPath,
		ServiceUnit:        unit,
		ClientTemplatePath: filepath.Join(openVPNDir, "client-template.txt"),
		TLSCryptKeyPath:    filepath.Join(openVPNDir, "tls-crypt.key"),
		TLSAuthKeyPath:     filepath.Join(openVPNDir, "tls-auth.key"),
	}
}

// Dots are permitted because existing EasyRSA PKIs commonly contain DNS-like
// client CNs. Slashes, whitespace and shell metacharacters remain rejected.
var validCN = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,64}$`)

// caArgs prepends EasyRSA global options needed for commands which use the CA
// private key. The passphrase itself is read by OpenSSL from a protected file;
// it is never included in argv, environment values, errors, or logs.
func (m *Manager) caArgs(args ...string) []string {
	out := []string{"--batch"}
	if m.CAPasswordFile != "" {
		out = append(out, "--passin=file:"+m.CAPasswordFile)
	}
	return append(out, args...)
}

func (m *Manager) AddClient(ctx context.Context, cn string) ([]byte, error) {
	return m.AddClientWithOptions(ctx, cn, ClientCreateOptions{})
}

func (m *Manager) AddClientWithOptions(ctx context.Context, cn string, opts ClientCreateOptions) ([]byte, error) {
	if !validCN.MatchString(cn) {
		return nil, fmt.Errorf("invalid common name: %q", cn)
	}
	certDays := opts.CertDays
	if certDays == 0 {
		certDays = defaultClientCertDays
	}
	if certDays < minClientCertDays || certDays > maxClientCertDays {
		return nil, fmt.Errorf("certificate validity must be between %d and %d days", minClientCertDays, maxClientCertDays)
	}
	if len(opts.Password) > 1024 {
		return nil, fmt.Errorf("client password is too long")
	}

	certs, err := ReadIndex(m.EasyRSADir)
	if err == nil {
		for _, c := range certs {
			if c.CommonName == cn && c.Status == "valid" {
				return nil, fmt.Errorf("client %q already exists", cn)
			}
		}
	}

	args := m.caArgs()
	var passFile string
	if opts.Password == "" {
		args = append(args, "build-client-full", cn, "nopass")
	} else {
		passFile, err = writePassphraseFile(opts.Password)
		if err != nil {
			return nil, fmt.Errorf("prepare client password: %w", err)
		}
		defer os.Remove(passFile)
		args = append(args, "--passout=file:"+passFile, "build-client-full", cn)
	}

	cmd := exec.CommandContext(ctx, "./easyrsa", args...)
	cmd.Dir = m.EasyRSADir
	cmd.Env = append(os.Environ(), "EASYRSA_CERT_EXPIRE="+strconv.Itoa(certDays))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("easyrsa build-client-full failed: %w\n%s", err, out)
	}

	bundle, err := m.buildOVPN(cn)
	if err != nil {
		return nil, fmt.Errorf("assemble .ovpn: %w", err)
	}
	if err := os.MkdirAll(m.ClientsDir, 0o755); err != nil {
		return nil, fmt.Errorf("ensure clients dir: %w", err)
	}
	dst := filepath.Join(m.ClientsDir, cn+".ovpn")
	if err := os.WriteFile(dst, bundle, 0o600); err != nil {
		return nil, fmt.Errorf("write %s: %w", dst, err)
	}
	return bundle, nil
}

func writePassphraseFile(password string) (string, error) {
	f, err := os.CreateTemp("", "openvpn-admin-pass-*")
	if err != nil {
		return "", err
	}
	path := f.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(path)
		}
	}()
	if err = f.Chmod(0o600); err != nil {
		_ = f.Close()
		return "", err
	}
	if _, err = f.WriteString(password + "\n"); err != nil {
		_ = f.Close()
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	return path, nil
}

func (m *Manager) BuildOVPN(cn string) ([]byte, error) {
	if !validCN.MatchString(cn) {
		return nil, fmt.Errorf("invalid common name: %q", cn)
	}
	return m.buildOVPN(cn)
}

func (m *Manager) buildOVPN(cn string) ([]byte, error) {
	pki := filepath.Join(m.EasyRSADir, "pki")
	tmpl, err := os.ReadFile(m.ClientTemplatePath)
	if err != nil {
		return nil, fmt.Errorf("read client template %s: %w", m.ClientTemplatePath, err)
	}
	ca, err := os.ReadFile(filepath.Join(pki, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("read ca.crt: %w", err)
	}
	crt, err := os.ReadFile(filepath.Join(pki, "issued", cn+".crt"))
	if err != nil {
		return nil, fmt.Errorf("read issued %s.crt: %w", cn, err)
	}
	key, err := os.ReadFile(filepath.Join(pki, "private", cn+".key"))
	if err != nil {
		return nil, fmt.Errorf("read private %s.key: %w", cn, err)
	}

	var b bytes.Buffer
	b.Write(tmpl)
	if !bytes.HasSuffix(tmpl, []byte("\n")) {
		b.WriteByte('\n')
	}
	b.WriteString("<ca>\n")
	b.Write(ca)
	b.WriteString("</ca>\n")
	b.WriteString("<cert>\n")
	b.Write(extractCertPEM(crt))
	b.WriteString("</cert>\n")
	b.WriteString("<key>\n")
	b.Write(key)
	b.WriteString("</key>\n")

	if data, err := os.ReadFile(m.TLSCryptKeyPath); err == nil {
		b.WriteString("<tls-crypt>\n")
		b.Write(data)
		b.WriteString("</tls-crypt>\n")
	} else if data, err := os.ReadFile(m.TLSAuthKeyPath); err == nil {
		b.WriteString("key-direction 1\n<tls-auth>\n")
		b.Write(data)
		b.WriteString("</tls-auth>\n")
	}
	return b.Bytes(), nil
}

func extractCertPEM(in []byte) []byte {
	const begin = "-----BEGIN CERTIFICATE-----"
	const end = "-----END CERTIFICATE-----"
	s := string(in)
	i := strings.Index(s, begin)
	j := strings.Index(s, end)
	if i < 0 || j < 0 {
		return in
	}
	return []byte(s[i:j+len(end)] + "\n")
}

func (m *Manager) RevokeClient(ctx context.Context, cn string) error {
	if !validCN.MatchString(cn) {
		return fmt.Errorf("invalid common name: %q", cn)
	}

	cmd := exec.CommandContext(ctx, "./easyrsa", m.caArgs("revoke", cn)...)
	cmd.Dir = m.EasyRSADir
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("easyrsa revoke %s: %w\n%s", cn, err, out)
	}

	cmd = exec.CommandContext(ctx, "./easyrsa", m.caArgs("gen-crl")...)
	cmd.Dir = m.EasyRSADir
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("easyrsa gen-crl: %w\n%s", err, out)
	}

	src := filepath.Join(m.EasyRSADir, "pki", "crl.pem")
	dst := filepath.Join(m.OpenVPNDir, "crl.pem")
	if data, err := os.ReadFile(src); err == nil {
		_ = os.WriteFile(dst, data, 0o644)
	}
	_ = os.Remove(filepath.Join(m.ClientsDir, cn+".ovpn"))
	return nil
}

func (m *Manager) IsServiceActive(ctx context.Context) bool {
	if m.ListenPort > 0 {
		return localPortListening(m.ListenProto, m.ListenPort)
	}
	cmd := exec.CommandContext(ctx, "systemctl", "is-active", m.ServiceUnit)
	out, _ := cmd.Output()
	return strings.TrimSpace(string(out)) == "active"
}

func localPortListening(proto string, port int) bool {
	proto = strings.ToLower(strings.TrimSpace(proto))
	var paths []string
	switch proto {
	case "tcp":
		paths = []string{"/proc/net/tcp", "/proc/net/tcp6"}
	case "udp":
		paths = []string{"/proc/net/udp", "/proc/net/udp6"}
	default:
		return false
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err == nil && portListed(data, port, proto == "tcp") {
			return true
		}
	}
	return false
}

func portListed(data []byte, port int, requireTCPListen bool) bool {
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] == "sl" {
			continue
		}
		local := fields[1]
		i := strings.LastIndexByte(local, ':')
		if i < 0 {
			continue
		}
		p, err := strconv.ParseUint(local[i+1:], 16, 16)
		if err != nil || int(p) != port {
			continue
		}
		if requireTCPListen && fields[3] != "0A" {
			continue
		}
		return true
	}
	return false
}

func (m *Manager) ServiceUptime(ctx context.Context) string {
	cmd := exec.CommandContext(ctx, "systemctl", "show", m.ServiceUnit, "--property=ActiveEnterTimestamp", "--value")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	ts := strings.TrimSpace(string(out))
	if ts == "" {
		return ""
	}
	t, err := time.Parse("Mon 2006-01-02 15:04:05 MST", ts)
	if err != nil {
		return ""
	}
	d := time.Since(t)
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	return fmt.Sprintf("%dd %02d:%02d", days, hours, mins)
}
