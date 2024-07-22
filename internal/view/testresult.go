package view

import (
	"bytes"
	"text/template"
)

type testResult struct {
	path string

	untested *untestedComponents
	issues   *issuesComponent
	summary  *summary

	str string
}

// GenerateSummary constructs a summary and generates it's string representation
// intended for human readable output.
//
// Function returns an error if generation of string representation fails.
func GenerateTestResult(path string, untested *untestedComponents, issues *issuesComponent, sum *summary) (testResult, error) {
	s := testResult{
		path: path,

		untested: untested,
		issues:   issues,
		summary:  sum,
	}

	if err := s.computeString(); err != nil {
		return s, err
	}

	return s, nil
}

func (r *testResult) computeString() error {
	var buff bytes.Buffer

	err := testResultTemplate.Execute(&buff, struct {
		Title string

		Untested string
		Issues   string
		Summary  string
	}{
		Title:    sectionStyle.Render("Testing " + r.path),
		Untested: r.untested.String(),
		Issues:   r.issues.String(),
		Summary:  r.summary.String(),
	})

	if err != nil {
		return err
	}

	r.str = buff.String()
	return nil
}

func (r *testResult) String() string {
	return r.str
}

var testResultTemplate *template.Template = template.Must(template.New("testResult").Parse(`
{{.Title}}

{{if not (.Untested | len | eq 0) }}{{.Untested}}
{{end}}
{{.Issues}}

{{.Summary}}`))
