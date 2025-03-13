package sbommonitor

import (
	"bytes"
	"fmt"
	"text/template"
)

type monitorProjectComponent struct {
	projectName string
	uri         string

	str string
}

func generateMonitorProjectComponent(projectName, uri string) (monitorProjectComponent, error) {
	mp := monitorProjectComponent{
		projectName: projectName,
		uri:         uri,
	}

	if err := mp.computeString(); err != nil {
		return mp, err
	}

	return mp, nil
}

func (m *monitorProjectComponent) getTitle() string {
	return fmt.Sprintf("Monitoring '%s'...", m.projectName)
}

func (m *monitorProjectComponent) computeString() error {
	var buff bytes.Buffer

	err := monitorProjectDetailsTemplate.Execute(&buff, struct {
		Title string
		URI   string
	}{
		Title: bold.Render(m.getTitle()),
		URI:   m.uri,
	})

	if err != nil {
		return err
	}

	m.str = buff.String()
	return nil
}

func (m *monitorProjectComponent) String() string {
	return m.str
}

var monitorProjectDetailsTemplate *template.Template = template.Must(
	template.New("sbomMonitorProject").Parse(`{{.Title}}

Explore this snapshot at {{.URI}}

Notifications about newly disclosed issues related to these dependencies will be emailed to you.`))
