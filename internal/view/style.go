package view

import "github.com/charmbracelet/lipgloss"

var (
	defaultColor = lipgloss.NoColor{}

	red     = lipgloss.AdaptiveColor{Light: "9", Dark: "1"}
	yellow  = lipgloss.AdaptiveColor{Light: "11", Dark: "3"}
	magenta = lipgloss.AdaptiveColor{Light: "13", Dark: "5"}

	// Severity styles renders severities combined with its color.
	lowStyle      = lipgloss.NewStyle().Foreground(defaultColor)
	mediumStyle   = lipgloss.NewStyle().Foreground(yellow)
	highStyle     = lipgloss.NewStyle().Foreground(red)
	criticalStyle = lipgloss.NewStyle().Foreground(magenta)

	sectionStyle = lipgloss.NewStyle().Bold(true)

	boxStyle = lipgloss.NewStyle().
			PaddingLeft(2).
			PaddingRight(4).
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(defaultColor)

	untestedStyle = lipgloss.NewStyle().
			Width(68).
			PaddingBottom(1).
			Border(lipgloss.NormalBorder(), false, false, true, false).
			BorderForeground(defaultColor)
)
