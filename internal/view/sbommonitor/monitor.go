package sbommonitor

import (
	"bytes"
	"html/template"
)

type monitorComponent struct {
	monitorProjects []monitorProjectComponent

	str string
}

func generateMonitorComponent(monitorProjects []monitorProjectComponent) (monitorComponent, error) {
	m := monitorComponent{monitorProjects: monitorProjects}

	if err := m.computeString(); err != nil {
		return m, err
	}

	return m, nil
}

func (m *monitorComponent) computeString() error {
	var buff bytes.Buffer

	var projects = make([]string, len(m.monitorProjects))
	for i, mp := range m.monitorProjects {
		projects[i] = mp.String()
	}

	err := monitorTemplate.Execute(&buff, struct {
		Projects []string
	}{
		Projects: projects,
	})

	if err != nil {
		return err
	}

	m.str = buff.String()
	return nil
}

func (m *monitorComponent) String() string {
	return m.str
}

var monitorTemplate *template.Template = template.Must(
	template.New("sbomMonitor").
		Parse(`{{- range $i, $project := .Projects}}
{{- if gt $i 0}}
─────────────────────────────────────────────────────
{{end}}
{{$project}}
{{end}}`))
