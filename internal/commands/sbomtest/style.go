package sbomtest

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
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

// LowStyle renders blue and bold.
var LowStyle = lipgloss.NewStyle().
	Bold(true).
	Foreground(lipgloss.AdaptiveColor{Light: "#0000FF", Dark: "#0000FF"})

// HighStyle renders red and bold.
var HighStyle = lipgloss.NewStyle().
	Bold(true).
	Foreground(lipgloss.AdaptiveColor{Light: "9", Dark: "9"})

// MediumStyle renders yellow and bold.
var MediumStyle = lipgloss.NewStyle().
	Bold(true).
	Foreground(lipgloss.AdaptiveColor{Light: "227", Dark: "227"})

// CriticalStyle renders magenta and bold.
var CriticalStyle = lipgloss.NewStyle().
	Bold(true).
	Foreground(lipgloss.AdaptiveColor{Light: "5", Dark: "5"})

func RenderTitle(severity, desc string) string {
	severity = strings.ToUpper(severity)
	title := fmt.Sprintf("✗ [%s] %s", severity, desc)

	switch severity {
	case "LOW":
		return LowStyle.Render(title)
	case "MEDIUM":
		return MediumStyle.Render(title)
	case "HIGH":
		return HighStyle.Render(title)
	case "CRITICAL":
		return CriticalStyle.Render(title)
	}

	return title
}
