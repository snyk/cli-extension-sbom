package sbomtest

import (
	"fmt"
	"strings"

	"golang.org/x/exp/slices"

	"github.com/snyk/cli-extension-sbom/internal/snykclient"
)

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
