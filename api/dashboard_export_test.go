package api

import (
	"strings"
	"testing"
)

func TestRewriteDashboardAddsExportControlsAndPrefix(t *testing.T) {
	input := `
    configURL: (cn) => "/api/v1/users/"+encodeURIComponent(cn)+"/config",
        h("button",{class:"btn btn--sm",title:"download .ovpn", onclick:()=>downloadOVPN(u.username)}, "↓ .ovpn"),
function signOut(){
`
	out := rewriteDashboard(input)
	for _, want := range []string{
		`exportURL: (cn,format) => "/ovpn/api/v1/exports/"`,
		`other export formats`,
		`function downloadExportPrompt(cn)`,
		`function downloadClientExport(cn, format)`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("rewritten dashboard missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, `"/api/v1/`) {
		t.Fatalf("root API path leaked into dashboard: %s", out)
	}
}
