package sbommonitor

import (
	"fmt"
	"io"

	"github.com/snyk/cli-extension-sbom/internal/snykclient"
)

func NewRenderer(w io.Writer) *Renderer {
	return &Renderer{
		w: w,
	}
}

type Renderer struct {
	w            io.Writer
	renderDivier bool
}

func (r *Renderer) RenderWarnings(warnings []*snykclient.ConversionWarning) error {
	return warningsTemplate.Execute(r.w, struct {
		Warnings []*snykclient.ConversionWarning
	}{
		Warnings: warnings,
	})
}

func (r *Renderer) RenderMonitor(m *snykclient.MonitorDependenciesResponse, merr error) error {
	var title string
	var uri string
	var errTitle string

	if m != nil {
		title = bold.Render(fmt.Sprintf("Monitoring '%s'...", m.ProjectName))
		uri = m.URI
	}

	if merr != nil {
		errTitle = bold.Render("Error")
	}

	err := monitorProjectDetailsTemplate.Execute(r.w, struct {
		Title         string
		URI           string
		RenderDivider bool
		Error         error
		ErrorTitle    string
	}{
		Title:         title,
		URI:           uri,
		RenderDivider: r.renderDivier,
		Error:         merr,
		ErrorTitle:    errTitle,
	})

	if err != nil {
		return fmt.Errorf("failed to render monitor: %w", err)
	}

	r.renderDivier = true

	return nil
}
