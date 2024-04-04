package sbomtest

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/snyk/go-application-framework/pkg/workflow"
	"golang.org/x/exp/slices"

	"github.com/snyk/cli-extension-sbom/internal/snykclient"
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
	result := snykclient.ToResources(resp.Included)

	var depsSection string

	if printDeps {
		depsSection = fmt.Sprintf("\n" + SectionStyle.Render("Packages:") + "\n")

		keys := make([]string, 0, len(result.Packages))
		for k := range result.Packages {
			keys = append(keys, k)
		}

		slices.Sort(keys)

		for _, k := range keys {
			pkg := result.Packages[k]
			depsSection += SprintDependencies(pkg.ID, pkg.PURL)
		}
	}

	issuesSection := fmt.Sprintf("\n" + SectionStyle.Render("Issues:") + "\n\n")

	vulns := SortVulns(result.Vulnerabilities)

	for i := range vulns {
		var introducedBy []string

		for _, pkg := range vulns[i].Packages {
			introducedBy = append(introducedBy, pkg.ID)
		}

		if len(introducedBy) == 0 {
			introducedBy = []string{"-"}
		} else {
			slices.Sort(introducedBy)
		}

		title := vulns[i].Title
		severity := vulns[i].SeverityLevel

		issuesSection += SprintIssue(title, vulns[i].ID, introducedBy, severity)
	}

	summary := fmt.Sprintf("Tested %d dependencies for known issues, found %d.\n\n",
		len(resp.Data.Attributes.Summary.Tested),
		resp.Data.Attributes.Summary.TotalIssues,
	)

	return fmt.Sprintf("Testing %s\n%s\n%s\n%s\n\n", dir, depsSection, issuesSection, summary)
}

func SprintDependencies(id, purl string) string {
	return fmt.Sprintf(`
  %s
  purl: %s
`, id, purl)
}

func SprintIssue(title, id string, introducedBy []string, severity snykclient.SeverityLevel) string {
	return fmt.Sprintf(`%s
    Introduced through: %s
    URL: https://security.snyk.io/vuln/%s

`, RenderTitle(severity, title), strings.Join(introducedBy, ","), id)
}

func SortVulns(vulns map[string]snykclient.VulnerabilityResource) []snykclient.VulnerabilityResource {
	result := make([]snykclient.VulnerabilityResource, 0, len(vulns))

	for id := range vulns {
		result = append(result, vulns[id])
	}

	slices.SortFunc(result, func(a, b snykclient.VulnerabilityResource) int {
		if a.SeverityLevel != b.SeverityLevel {
			return int(a.SeverityLevel - b.SeverityLevel)
		}

		if a.ID < b.ID {
			return -1
		}

		if a.ID > b.ID {
			return +1
		}

		return 0
	})

	return result
}
