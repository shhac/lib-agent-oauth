package oauth

import "html/template"

var enrollTmpl = template.Must(template.New("enroll").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{if .Title}}{{.Title}}{{else}}Set up credentials{{end}}</title>
<style>
` + basePageCSS + `
input[type=text],input[type=password]{font-size:1rem;padding:.55rem;width:100%;box-sizing:border-box;margin-top:.25rem}
fieldset{border:1px solid #ccc;border-radius:.4rem;margin-top:1rem;padding:.75rem 1rem}
label.field{display:block;margin-top:.75rem}
.err{color:#b00020;border:1px solid #b00020;border-radius:.4rem;padding:.5rem .75rem}
.help{color:#555;font-size:.85rem;margin:.15rem 0 0}
.snippet{display:flex;align-items:stretch;gap:.4rem;margin:.4rem 0 0}
.snippet pre{flex:1;margin:0;padding:.5rem .6rem;background:#f4f4f4;border:1px solid #ddd;border-radius:.4rem;font-size:.8rem;overflow-x:auto;user-select:all;white-space:pre-wrap;word-break:break-all}
.snippet button{font-size:.8rem;padding:0 .7rem;cursor:pointer;border:1px solid #ccc;border-radius:.4rem;background:#fff}
</style></head><body>
<h1>{{if .Title}}{{.Title}}{{else}}Set up credentials{{end}}</h1>
<p class="muted">Hi {{.Principal}} — one-time setup{{if .ClientName}} to finish connecting “{{.ClientName}}”{{end}}.</p>
{{if .Intro}}<p class="muted">{{.Intro}}</p>{{end}}
{{if .Error}}<p class="err">{{.Error}}</p>{{end}}
<form method="post" action="{{.Action}}" autocomplete="off">
{{$single := .SingleMode}}
{{range .Modes}}
  <fieldset>
    {{if not $single}}<label><input type="radio" name="enroll_mode" value="{{.Key}}"{{if .Selected}} checked{{end}}> {{.Label}}</label>
    {{else}}<input type="hidden" name="enroll_mode" value="{{.Key}}">{{if .Label}}<legend>{{.Label}}</legend>{{end}}{{end}}
    {{range .Fields}}
    <label class="field">{{.Label}}{{if .Optional}} <span class="muted">(optional)</span>{{end}}
      <input type="{{if .Secret}}password{{else}}text{{end}}" name="{{.Name}}" value="{{.Value}}" autocomplete="off">
    </label>
    {{if .Help}}<p class="help">{{.Help}}</p>{{end}}
    {{if .Snippet}}<div class="snippet"><pre>{{.Snippet}}</pre><button type="button" onclick="navigator.clipboard.writeText(this.previousElementSibling.textContent)">Copy</button></div>{{end}}
    {{end}}
  </fieldset>
{{end}}
  {{range $k, $v := .Hidden}}<input type="hidden" name="{{$k}}" value="{{$v}}">{{end}}
  <button type="submit">Verify &amp; continue</button>
</form>
</body></html>`))
