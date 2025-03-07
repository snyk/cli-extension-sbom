package sbommonitor

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/snyk/cli-extension-sbom/internal/snykclient"
)

func presentSBOMMonitor(monitors []snykclient.MonitorDepsResponse) string {
	var body = make([]string, 0)

	for i, m := range monitors {
		if i > 0 {
			body = append(body, renderDivider())
		}

		body = append(
			body,
			renderTitle(fmt.Sprintf("Monitoring '%s'...", m.ProjectName)),
			"Explore this snapshot at "+renderLink(m.URI)+renderNewLine(),
			"Notifications about newly disclosed issues related to these dependencies will be emailed to you.",
		)
	}

	return strings.Join(body, "\n") + renderNewLine()
}

func renderBold(str string) string {
	return lipgloss.NewStyle().Bold(true).Render(str)
}

func renderLink(str string) string {
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color("12")).
		Render(str)
}

func renderDivider() string {
	return "\n─────────────────────────────────────────────────────"
}

func renderNewLine() string {
	return "\n"
}

func renderTitle(str string) string {
	return fmt.Sprintf("\n%s\n", renderBold(str))
}
