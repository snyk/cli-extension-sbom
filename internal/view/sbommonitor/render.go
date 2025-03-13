package sbommonitor

import (
	"io"

	"github.com/snyk/cli-extension-sbom/internal/snykclient"
)

func RenderMonitor(dst io.Writer, monitors []*snykclient.MonitorDependenciesResponse) (int, error) {
	var mp = make([]monitorProjectComponent, len(monitors))

	for i, m := range monitors {
		c, err := generateMonitorProjectComponent(m.ProjectName, m.URI)
		if err != nil {
			return 0, err
		}
		mp[i] = c
	}

	monitor, err := generateMonitorComponent(mp)
	if err != nil {
		return 0, err
	}

	return io.WriteString(dst, monitor.String())
}
