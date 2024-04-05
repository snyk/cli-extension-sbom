package sbomtest

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"

	"github.com/snyk/cli-extension-sbom/internal/snykclient"
)

var (
	SectionStyle = lipgloss.NewStyle().Bold(true)

	red     = lipgloss.Color("1")
	yellow  = lipgloss.Color("3")
	magenta = lipgloss.Color("5")

	noColor = lipgloss.NoColor{} // Usually white or black

	// Severity styles renders severities in bold combined with it's color.
	severityStyle = lipgloss.NewStyle().Bold(true)

	lowStyle      = severityStyle.Copy().Foreground(noColor)
	mediumStyle   = severityStyle.Copy().Foreground(yellow)
	highStyle     = severityStyle.Copy().Foreground(red)
	criticalStyle = severityStyle.Copy().Foreground(magenta)
)

func RenderUntestedComponent(ref, reason string) string {
	title := mediumStyle.Render(fmt.Sprintf(`✗ %s`, ref))
	return fmt.Sprintf("%s\n    %s", title, reason)
}

func RenderTitle(severity snykclient.SeverityLevel, desc string) string {
	title := fmt.Sprintf("✗ [%s] %s", severity, desc)

	switch severity {
	case snykclient.LowSeverity:
		return lowStyle.Render(title)
	case snykclient.MediumSeverity:
		return mediumStyle.Render(title)
	case snykclient.HighSeverity:
		return highStyle.Render(title)
	case snykclient.CriticalSeverity:
		return criticalStyle.Render(title)
	}

	return title
}
