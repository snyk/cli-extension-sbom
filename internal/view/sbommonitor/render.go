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

func (r *Renderer) RenderMonitor(m *snykclient.MonitorDependenciesResponse) error {
	err := monitorProjectDetailsTemplate.Execute(r.w, struct {
		Title         string
		URI           string
		RenderDivider bool
	}{
		Title:         bold.Render(fmt.Sprintf("Monitoring '%s'...", m.ProjectName)),
		URI:           m.URI,
		RenderDivider: r.renderDivier,
	})

	if err != nil {
		return fmt.Errorf("failed to render monitor: %w", err)
	}

	r.renderDivier = true

	return nil
}

func (*Renderer) RenderMonitorError(err error) {
	panic("not implemented")
}
