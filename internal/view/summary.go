package view

import (
	"bytes"
	"fmt"
	"html/template"
	"strconv"
)

type Summary struct {
	Critical int
	High     int
	Medium   int
	Low      int

	TotalIssues int
}

type summary struct {
	org  string
	path string

	critical int
	high     int
	medium   int
	low      int

	totalIssues int

	str string
}

// generateSummary constructs a summary and generates it's string representation
// intended for human readable output.
//
// Function returns an error if generation of string representation fails.
func generateSummary(org, path string, sum Summary) (*summary, error) {
	s := summary{
		org:  org,
		path: path,

		critical: sum.Critical,
		high:     sum.High,
		medium:   sum.Medium,
		low:      sum.Low,

		totalIssues: sum.TotalIssues,
	}

	if err := s.computeString(); err != nil {
		return nil, err
	}

	return &s, nil
}

func (s *summary) computeString() error {
	var buff bytes.Buffer

	err := summaryTemplate.Execute(&buff, struct {
		Title string

		Org  string
		Type string
		Path string

		OpenIssues string
	}{
		Title: sectionStyle.Render("Test summary"),
		Org:   s.org,
		Type:  "Software Bill of Materials",
		Path:  s.path,

		OpenIssues: s.issuesCounter(),
	})

	if err != nil {
		return err
	}

	s.str = buff.String()
	return nil
}

func (s *summary) String() string {
	return boxStyle.Render(s.str)
}

var summaryTemplate *template.Template = template.Must(template.New("summary").Parse(`{{.Title}}
  Organization:    {{.Org}}
  Test type:       {{.Type}}
  Path:            {{.Path}}

  Open issues:     {{.OpenIssues}}`))

func (s *summary) issuesCounter() string {
	total := sectionStyle.Render(strconv.Itoa(s.totalIssues))

	if s.totalIssues == 0 {
		return total
	}

	var levels string

	if s.critical > 0 {
		levels += criticalStyle.Render(fmt.Sprintf("%d CRITICAL", s.critical))
	}

	if s.high > 0 {
		levels += highStyle.Render(fmt.Sprintf("  %d HIGH", s.high))
	}

	if s.medium > 0 {
		levels += mediumStyle.Render(fmt.Sprintf("  %d MEDIUM", s.medium))
	}

	if s.low > 0 {
		levels += lowStyle.Render(fmt.Sprintf("  %d LOW", s.low))
	}

	return fmt.Sprintf("%s [ %s ]", total, levels)
}
