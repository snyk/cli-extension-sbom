package sbommonitor

import (
	"text/template"
)

var monitorProjectDetailsTemplate *template.Template = template.Must(
	template.New("sbomMonitorProject").Parse(
		`{{ if .RenderDivider }}
─────────────────────────────────────────────────────
{{ end }}
{{.Title}}

Explore this snapshot at {{.URI}}

Notifications about newly disclosed issues related to these dependencies will be emailed to you.
`))
