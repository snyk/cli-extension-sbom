package view

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/snyk/cli-extension-sbom/internal/severities"
)

type OpenIssue struct {
	Severity     severities.Level
	Description  string
	IntroducedBy []string
	SnykRef      string
}

type openIssue struct {
	Severity     string
	Description  string
	IntroducedBy []string
	SnykRef      string
}

type issuesComponent struct {
	title  string
	issues []openIssue

	str string
}

func renderSeverity(style lipgloss.Style, severity string) string {
	return style.Render(
		fmt.Sprintf("× [%s]", severity),
	)
}

// generateIssues constructs a list of issues and severities and generates it's
// string representation intended for human readable output.
//
// Function returns an error if generation of string representation fails.
func generateIssues(issues ...OpenIssue) (*issuesComponent, error) {
	if len(issues) == 0 {
		return &issuesComponent{
			str: fmt.Sprintf(
				"%s No issues found.",
				renderSeverity(successStyle, "SUCCESS"),
			),
		}, nil
	}

	result := issuesComponent{
		title:  sectionStyle.Render("Open issues:"),
		issues: make([]openIssue, len(issues)),
	}

	for i := range issues {
		style := lowStyle

		switch issues[i].Severity {
		case severities.LowSeverity:
			style = lowStyle

		case severities.MediumSeverity:
			style = mediumStyle

		case severities.HighSeverity:
			style = highStyle

		case severities.CriticalSeverity:
			style = criticalStyle
		}

		result.issues[i] = openIssue{
			Severity:    renderSeverity(style, issues[i].Severity.String()),
			Description: sectionStyle.Render(issues[i].Description),
			SnykRef:     issues[i].SnykRef,
		}

		result.issues[i].IntroducedBy = make([]string, len(issues[i].IntroducedBy))
		copy(result.issues[i].IntroducedBy, issues[i].IntroducedBy)
	}

	if err := result.computeString(); err != nil {
		return nil, err
	}

	return &result, nil
}

func (s *issuesComponent) computeString() error {
	var buff bytes.Buffer

	err := issuesTemplate.Execute(&buff, struct {
		Title  string
		Issues []openIssue
	}{
		Title:  sectionStyle.Render("Open issues:"),
		Issues: s.issues,
	})

	if err != nil {
		return err
	}

	s.str = buff.String()
	s.str = s.str[:len(s.str)-1]

	return nil
}

func (s *issuesComponent) String() string {
	return s.str
}

var issuesTemplate *template.Template = template.Must(
	template.New("untestedComponents").
		Funcs(template.FuncMap{
			"join": strings.Join,
		}).
		Parse(`{{.Title}}
{{range .Issues}}
{{.Severity}} {{.Description}}
  Introduced through: {{join .IntroducedBy ", "}}
  URL: https://security.snyk.io/vuln/{{.SnykRef}}
{{end}}`),
)
