package sbomtest

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"

	"github.com/snyk/cli-extension-sbom/internal/snykclient"
)

var (
	SectionStyle = lipgloss.NewStyle().Bold(true)

	red     = lipgloss.AdaptiveColor{Light: "9", Dark: "1"}
	yellow  = lipgloss.AdaptiveColor{Light: "11", Dark: "3"}
	magenta = lipgloss.AdaptiveColor{Light: "13", Dark: "5"}

	noColor = lipgloss.NoColor{} // Usually white or black

	// Severity styles renders severities in bold combined with it's color.
	severityStyle = lipgloss.NewStyle().Bold(true)

	lowStyle      = severityStyle.Copy().Foreground(noColor)
	mediumStyle   = severityStyle.Copy().Foreground(yellow)
	highStyle     = severityStyle.Copy().Foreground(red)
	criticalStyle = severityStyle.Copy().Foreground(magenta)
)

func RenderUntestedComponent(ref, reason string) string {
	title := lowStyle.Render(fmt.Sprintf(`× %s`, ref))
	return fmt.Sprintf("%s\n  Info: %s", title, reason)
}

func RenderTitle(severity snykclient.SeverityLevel, desc string) string {
	severityText := fmt.Sprintf("× [%s]", severity)

	style := lowStyle

	switch severity {
	case snykclient.LowSeverity:
		style = lowStyle

	case snykclient.MediumSeverity:
		style = mediumStyle

	case snykclient.HighSeverity:
		style = highStyle

	case snykclient.CriticalSeverity:
		style = criticalStyle
	}

	return fmt.Sprintf("%s %s", style.Render(severityText), SectionStyle.Render(desc))
}
