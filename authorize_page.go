package oauth

import (
	"fmt"
	"html/template"
	"net/http"
)

// basePageCSS is the styling shared by every browser page the OAuth flow
// serves — the approval form, the enrollment form, the chooser, and the fatal
// error page. Each template appends its own page-specific rules after it.
const basePageCSS = `body{font-family:system-ui,sans-serif;max-width:30rem;margin:4rem auto;padding:0 1.25rem;color:#111}
h1{font-size:1.4rem}
button{font-size:1rem;padding:.6rem 1.2rem;margin-top:1rem;cursor:pointer}
.muted{color:#555;font-size:.9rem}`

var authorizeTmpl = template.Must(template.New("authorize").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize</title>
<style>
` + basePageCSS + `
input{font-size:1rem;padding:.55rem;width:100%;box-sizing:border-box;margin-top:.25rem}
.err{color:#b00020}
</style></head><body>
<h1>Connect {{if .ClientName}}“{{.ClientName}}”{{else}}this client{{end}}?</h1>
{{if .SessionName}}<p class="muted">You're recognized as <b>{{.SessionName}}</b> from an earlier
login — authorize to continue, or enter a different pairing code below.</p>
{{else}}<p class="muted">Enter the pairing code printed in the server's terminal to let this
client call your tools. It then acts with your credentials.</p>{{end}}
{{if .Error}}<p class="err">{{.Error}}</p>{{end}}
<form method="post" action="{{.Action}}">
  <label>Pairing code{{if .SessionName}} <span class="muted">(optional)</span>{{end}}
    <input type="password" name="pairing_code" placeholder="mcp-XXXXX-XXXXX-…"{{if not .SessionName}} autofocus{{end}} autocomplete="off">
  </label>
  {{if .OfferUpdate}}<label class="muted" style="display:block;margin-top:.5rem">
    <input type="checkbox" name="update_credentials" value="1"> Update my stored credentials
  </label>{{end}}
  {{range $k, $v := .Hidden}}<input type="hidden" name="{{$k}}" value="{{$v}}">{{end}}
  <button type="submit"{{if .SessionName}} autofocus{{end}}>Authorize</button>
</form>
</body></html>`))

// renderForm shows the pairing-code form, echoing the request as hidden
// fields. A non-empty sessionName renders the returning-person variant: the
// code input turns optional and the button takes focus.
func (s *Server) renderForm(w http.ResponseWriter, client Client, p authParams, errMsg, sessionName string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = authorizeTmpl.Execute(w, map[string]any{
		"Action":      AuthorizePath,
		"ClientName":  client.Name,
		"Error":       errMsg,
		"SessionName": sessionName,
		// The re-enrollment affordance: only meaningful when this request's
		// resource has enrollment configured; a tick by the anonymous
		// operator is a no-op.
		"OfferUpdate": s.enrollmentFor(p) != nil,
		"Hidden":      p.hiddenFields(),
	})
}

// authorizeErrorPage renders a fatal authorization error (no safe redirect).
func (s *Server) authorizeErrorPage(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = fmt.Fprintf(w, `<!doctype html><html lang="en"><head><meta charset="utf-8">`+
		`<title>Cannot authorize</title><style>`+basePageCSS+`</style></head>`+
		`<body><h1>Cannot authorize</h1><p>%s</p></body></html>`, template.HTMLEscapeString(msg))
}
