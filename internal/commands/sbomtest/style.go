package sbomtest

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"

	"github.com/snyk/cli-extension-sbom/internal/snykclient"
)

type Mode int

/*
const (
	JSONOutput Mode = iota
	HumanReadable
	HumanReadableWithDeps
	HumanReadableWithDepsAndPaths
)

func GetPrintMode(printJSON, printDeps, printPaths bool) Mode {
	switch {
	case printJSON:
		return JSONOutput
	case printDeps && printPaths:
		return HumanReadableWithDepsAndPaths
	case printDeps:
		return HumanReadableWithDeps
	default:
		return HumanReadable
	}
}
*/

type Result struct {
	Doc      any
	MIMEType string
}

// SectionStyle renders blue and bold.
var SectionStyle = lipgloss.NewStyle().
	Bold(true)

// LowStyle renders white and bold.
var LowStyle = lipgloss.NewStyle().
	Bold(true).
	Foreground(lipgloss.NoColor{}) // White

// MediumStyle renders yellow and bold.
var MediumStyle = lipgloss.NewStyle().
	Bold(true).
	Foreground(lipgloss.Color("3")) // Yellow

// HighStyle renders red and bold.
var HighStyle = lipgloss.NewStyle().
	Bold(true).
	Foreground(lipgloss.Color("1")) // Red

// CriticalStyle renders magenta and bold.
var CriticalStyle = lipgloss.NewStyle().
	Bold(true).
	Foreground(lipgloss.Color("5")) // Magenta

func RenderTitle(severity snykclient.SeverityLevel, desc string) string {
	title := fmt.Sprintf("✗ [%s] %s", severity, desc)

	switch severity {
	case snykclient.LowSeverity:
		return LowStyle.Render(title)
	case snykclient.MediumSeverity:
		return MediumStyle.Render(title)
	case snykclient.HighSeverity:
		return HighStyle.Render(title)
	case snykclient.CriticalSeverity:
		return CriticalStyle.Render(title)
	}

	return title
}
