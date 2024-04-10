package sbomtest

import (
	"fmt"
	"html/template"

	"github.com/charmbracelet/lipgloss"

	"github.com/snyk/cli-extension-sbom/internal/snykclient"
)

var (
	SectionStyle = lipgloss.NewStyle().Bold(true)

	red     = lipgloss.AdaptiveColor{Light: "9", Dark: "1"}
	yellow  = lipgloss.AdaptiveColor{Light: "11", Dark: "3"}
	magenta = lipgloss.AdaptiveColor{Light: "13", Dark: "5"}

	noColor = lipgloss.NoColor{} // Usually white or black

	// Severity styles renders severities combined with its color.
	severityStyle = lipgloss.NewStyle()

	lowStyle      = severityStyle.Copy().Foreground(noColor)
	mediumStyle   = severityStyle.Copy().Foreground(yellow)
	highStyle     = severityStyle.Copy().Foreground(red)
	criticalStyle = severityStyle.Copy().Foreground(magenta)

	BoxStyle = lipgloss.NewStyle().
			PaddingLeft(2).
			PaddingRight(4).
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(noColor)
)

func RenderUntestedComponent(ref, reason string) string {
	title := fmt.Sprintf(`× %s`, SectionStyle.Render(ref))
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

var SummaryTemplate *template.Template = template.Must(template.New("summary").Parse(`{{.Title}}
  Organization:    {{.Org}}
  Test type:       {{.Type}}
  Path:            {{.Path}}

  Open issues:     {{.OpenIssues}}`))
