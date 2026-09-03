package ovpn

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ClientExport is a generated client credential artifact ready to download.
type ClientExport struct {
	Data        []byte
	Filename    string
	ContentType string
}

type clientExportSpec struct {
	command     string
	relPath     func(string) string
	filenameExt string
	contentType string
	protectable bool
}

var clientExportSpecs = map[string]clientExportSpec{
	"p12": {
		command:     "export-p12",
		relPath:     func(cn string) string { return filepath.Join("pki", "private", cn+".p12") },
		filenameExt: ".p12",
		contentType: "application/x-pkcs12",
		protectable: true,
	},
	"p7": {
		command:     "export-p7",
		relPath:     func(cn string) string { return filepath.Join("pki", "issued", cn+".p7b") },
		filenameExt: ".p7b",
		contentType: "application/pkcs7-mime",
	},
	"p8": {
		command:     "export-p8",
		relPath:     func(cn string) string { return filepath.Join("pki", "private", cn+".p8") },
		filenameExt: ".p8",
		contentType: "application/pkcs8",
		protectable: true,
	},
	"p1": {
		command:     "export-p1",
		relPath:     func(cn string) string { return filepath.Join("pki", "private", cn+".p1") },
		filenameExt: ".p1",
		contentType: "application/x-pem-file",
		protectable: true,
	},
}

// ExportClient generates an EasyRSA client credential in a supported format.
func (m *Manager) ExportClient(ctx context.Context, cn, format string) (*ClientExport, error) {
	return m.ExportClientProtected(ctx, cn, format, "")
}

// ExportClientProtected optionally protects formats containing private-key
// material. Passwords are passed to EasyRSA through a temporary 0600 file and
// are never placed directly in argv or persisted by the application.
func (m *Manager) ExportClientProtected(ctx context.Context, cn, format, password string) (*ClientExport, error) {
	if !validCN.MatchString(cn) {
		return nil, fmt.Errorf("invalid common name: %q", cn)
	}
	if len(password) > 1024 {
		return nil, fmt.Errorf("export password is too long")
	}

	format = strings.ToLower(strings.TrimSpace(format))
	if format == "ovpn" {
		if password != "" {
			return nil, fmt.Errorf("ovpn protection is set when the client is created")
		}
		data, err := m.BuildOVPN(cn)
		if err != nil {
			return nil, err
		}
		return &ClientExport{Data: data, Filename: cn + ".ovpn", ContentType: "application/x-openvpn-profile"}, nil
	}

	if format == "inline" {
		if password != "" {
			return nil, fmt.Errorf("inline export uses the client key's existing protection")
		}
		return m.exportInline(ctx, cn)
	}

	spec, ok := clientExportSpecs[format]
	if !ok {
		return nil, fmt.Errorf("unsupported export format: %q", format)
	}
	if password != "" && !spec.protectable {
		return nil, fmt.Errorf("format %q does not contain private-key material to password-protect", format)
	}

	args := []string{"--batch"}
	if password == "" {
		args = append(args, "--nopass")
	} else {
		passFile, err := writePassphraseFile(password)
		if err != nil {
			return nil, fmt.Errorf("prepare export password: %w", err)
		}
		defer os.Remove(passFile)
		args = append(args, "--passout=file:"+passFile)
	}
	args = append(args, spec.command, cn)

	cmd := exec.CommandContext(ctx, "./easyrsa", args...)
	cmd.Dir = m.EasyRSADir
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("easyrsa %s failed: %w\n%s", spec.command, err, out)
	}

	path := filepath.Join(m.EasyRSADir, spec.relPath(cn))
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read EasyRSA export %s: %w", path, err)
	}
	_ = os.Remove(path)

	return &ClientExport{Data: data, Filename: cn + spec.filenameExt, ContentType: spec.contentType}, nil
}

func (m *Manager) exportInline(ctx context.Context, cn string) (*ClientExport, error) {
	cmd := exec.CommandContext(ctx, "./easyrsa", "--batch", "inline", cn)
	cmd.Dir = m.EasyRSADir
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("easyrsa inline failed: %w\n%s", err, out)
	}

	candidates := []string{
		filepath.Join(m.EasyRSADir, "pki", "inline", "private", cn+".inline"),
		filepath.Join(m.EasyRSADir, "pki", "inline", cn+".inline"),
	}
	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err == nil {
			_ = os.Remove(path)
			return &ClientExport{Data: data, Filename: cn + ".inline", ContentType: "text/plain; charset=utf-8"}, nil
		}
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("read EasyRSA inline export %s: %w", path, err)
		}
	}
	return nil, fmt.Errorf("EasyRSA inline export for %q was not created", cn)
}
