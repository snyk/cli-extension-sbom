//nolint:tagliatelle // Disabling for snake-case in JSON payloads.
package sbomtest

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/snyk/cli-extension-sbom/internal/snykclient"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

type presenterFormat int

const (
	PresenterFormatPretty presenterFormat = iota
	PresenterFormatJSON

	MIMETypeJSON = "application/json"
	MIMETypeText = "text/plain"
)

type Presenter struct {
	format presenterFormat
}

func newPresenter(ictx workflow.InvocationContext) *Presenter {
	f := PresenterFormatPretty

	if ictx.GetConfiguration().GetBool("json") {
		f = PresenterFormatJSON
	}

	return &Presenter{
		format: f,
	}
}

func (p Presenter) Render(result *snykclient.GetSBOMTestResultResponseBody) (data []byte, contentType string, err error) {
	switch p.format {
	default:
		return nil, "", errors.New("presenter has no format")
	case PresenterFormatJSON:
		return renderJSONResult(result)
	case PresenterFormatPretty:
		return renderPrettyResult(result)
	}
}

type JSONOutput struct {
	OK              bool             `json:"ok"`
	DependencyCount int              `json:"dependencyCount"`
	UniqueCount     int              `json:"uniqueCount"`
	Summary         string           `json:"summary"`
	Remediation     interface{}      `json:"remediation,omitempty"`
	Filtered        interface{}      `json:"filtered,omitempty"`
	Vulnerabilities []*Vulnerability `json:"vulnerabilities"`
}

type Vulnerability struct {
	ID    string
	Title string
}

func resultToJSONOutput(body *snykclient.GetSBOMTestResultResponseBody) JSONOutput {
	vulns := make([]*Vulnerability, 0)
	res := body.Data.Attributes

	return JSONOutput{
		OK:              res.Summary.TotalIssues == 0,
		DependencyCount: len(res.Summary.Tested) + len(res.Summary.Untested),
		UniqueCount:     133, // what is this??
		Summary:         fmt.Sprintf("Found %d vulnerabilities", res.Summary.TotalVulnerabilities),
		Vulnerabilities: vulns,
	}
}

func renderJSONResult(result *snykclient.GetSBOMTestResultResponseBody) (data []byte, contentType string, err error) {
	contentType = MIMETypeJSON

	data, err = json.Marshal(resultToJSONOutput(result))
	if err != nil {
		return nil, contentType, err
	}

	return data, contentType, nil
}

func renderPrettyResult(result *snykclient.GetSBOMTestResultResponseBody) (data []byte, contentType string, err error) {
	// TODO: this is a mock template. Should get replaced.
	tpl := `TEST RESULTS
------------
❌ Found a total of %d vulnerabilities
`

	return []byte(fmt.Sprintf(tpl, result.Data.Attributes.Summary.TotalVulnerabilities)), MIMETypeText, nil
}

func AsHumanReadable(dir string, resp *snykclient.GetSBOMTestResultResponseBody, printDeps bool) string {
	view := snykclient.SortIncludes(resp.Included)

	var pkgs string

	if printDeps {
		pkgs = fmt.Sprintf("\n" + SectionStyle.Render("Packages:") + "\n\n")

		for _, val := range view.Packages {
			pkgs += fmt.Sprintf(`
  %s
  purl: %s
`, val.ID, val.Attributes.Purl)
		}
	}

	issues := fmt.Sprintf("\n" + SectionStyle.Render("Issues:") + "\n\n")

	for _, val := range view.Vulnerabilities {
		id := val.ID

		name, ok := view.Relationship[val.ID]
		if !ok {
			name = "-"
		}

		title := val.Attributes.Title
		severity := val.Attributes.EffectiveSeverityLevel

		issues += fmt.Sprintf(`%s
    Introduced through: %s
    URL: https://security.snyk.io/vuln/%s

`, RenderTitle(severity.String(), title), name, id)
	}

	summary := fmt.Sprintf("Tested %d dependencies for known issues, found %d.\n\n",
		len(resp.Data.Attributes.Summary.Tested),
		resp.Data.Attributes.Summary.TotalIssues,
	)

	return fmt.Sprintf("Testing %s\n%s\n%s\n%s\n\n", dir, pkgs, issues, summary)
}
