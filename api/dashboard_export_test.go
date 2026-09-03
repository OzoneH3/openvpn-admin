package api

import (
	"strings"
	"testing"
)

func TestRewriteDashboardAddsExportControlsCreateOptionsAndPrefix(t *testing.T) {
	input := `
    addUser: (username) => call("POST","/api/v1/users",{username}),
    configURL: (cn) => "/api/v1/users/"+encodeURIComponent(cn)+"/config",
        h("button",{class:"btn btn--sm",title:"download .ovpn", onclick:()=>downloadOVPN(u.username)}, "↓ .ovpn"),
function signOut(){
`
	out := rewriteDashboard(input)
	for _, want := range []string{
		`exportURL: (cn,format) => "/ovpn/api/v1/exports/"`,
		`Certificate validity in days (1-3650)`,
		`Client private-key password`,
		`↓ .p12`,
		`↓ .p7b`,
		`↓ .p8`,
		`↓ .p1`,
		`↓ inline`,
		`async function downloadClientExport(cn, format, protectable)`,
		`JSON.stringify({password})`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("rewritten dashboard missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, `"/api/v1/`) {
		t.Fatalf("root API path leaked into dashboard: %s", out)
	}
}
