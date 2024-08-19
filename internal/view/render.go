package view

import (
	"io"

	"golang.org/x/exp/slices"
)

type Presentation struct {
	Org, Path string
	Untested  []Component
	Issues    []OpenIssue
	Summary   Summary
	Warnings  []Warning
}

// Render will combine and _mutate_ data to construct view with issues sorted
// using this precedence: severity, vulnerability reference, first package in
// introducedBy. The string result will be written to dst as a bytes.
//
// Notice: This function may alter incoming data, such as the order of elements
// in the issues parameter.
func Render(dst io.Writer, p *Presentation) (int, error) {
	untestedView, err := generateUntestedComponents(p.Untested...)
	if err != nil {
		return 0, err
	}

	warningsView, err := generateWarnings(p.Warnings...)
	if err != nil {
		return 0, err
	}

	sortIssues(p.Issues)

	issuesView, err := generateIssues(p.Issues...)
	if err != nil {
		return 0, err
	}

	summaryView, err := generateSummary(p.Org, p.Path, p.Summary)
	if err != nil {
		return 0, err
	}

	result, err := GenerateTestResult(
		p.Path,
		untestedView,
		warningsView,
		issuesView,
		summaryView)
	if err != nil {
		return 0, err
	}

	n, err := io.WriteString(dst, result.String())
	if err != nil {
		return n, err
	}

	return n, nil
}

func sortIssues(issues []OpenIssue) {
	slices.SortFunc(issues, func(a, b OpenIssue) int {
		if a.Severity != b.Severity {
			return int(a.Severity - b.Severity)
		}

		if a.SnykRef < b.SnykRef {
			return -1
		}

		if a.SnykRef > b.SnykRef {
			return +1
		}

		if a.IntroducedBy[0].PURL < b.IntroducedBy[0].PURL {
			return -1
		}

		if a.IntroducedBy[0].PURL > b.IntroducedBy[0].PURL {
			return +1
		}

		return 0
	})
}
