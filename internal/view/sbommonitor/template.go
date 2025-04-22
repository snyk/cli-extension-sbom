package sbommonitor

import (
	"text/template"
)

var warningsTemplate *template.Template = template.Must(
	template.New("sbomMonitorWarnings").Parse(
		`{{range .Warnings -}}
WARNING: [{{.Type}}] {{.Msg -}}
{{if gt (len .BOMRef) 0}} ({{.BOMRef}}){{end}}
{{end}}
{{- if gt (len .Warnings) 0}}
─────────────────────────────────────────────────────

{{ end -}}
`),
)

var monitorProjectDetailsTemplate *template.Template = template.Must(
	template.New("sbomMonitorProject").Parse(
		`{{ if .RenderDivider }}
─────────────────────────────────────────────────────

{{ end -}}
{{- if .Error -}}

{{ .ErrorTitle }}

An error occurred while attempting to monitor parts of the SBOM document.

Details:
	{{ .Error }}

{{- else -}}

{{ .Title }}

Explore this snapshot at {{ .URI }}

Notifications about newly disclosed issues related to these dependencies will be emailed to you.

{{- end }}
`))
