package sbomtest

import (
	"fmt"
	"strings"

	"golang.org/x/exp/slices"

	"github.com/snyk/cli-extension-sbom/internal/snykclient"
)

func renderPrettyResult(path string, body *snykclient.GetSBOMTestResultResponseBody, printDeps bool) (data []byte, contentType string, err error) {
	resources := snykclient.ToResources(
		body.Data.Attributes.Summary.Tested,
		body.Data.Attributes.Summary.Untested,
		body.Included,
	)

	output := AsHumanReadable(path, resources, printDeps)

	return []byte(output), MIMETypeText, nil
}

func AsHumanReadable(path string, resources snykclient.Resources, printDeps bool) string {
	summary := SprintSummary(resources)

	var untestedSection string
	if len(resources.Untested) > 0 {
		untestedSection = SprintUntestedComponents(resources) + "\n"
	}

	if len(resources.Tested) == 0 {
		return fmt.Sprintf("Testing %s\n%s%s\n\n", path, untestedSection, summary)
	}

	var depsSection string

	if printDeps {
		depsSection = SprintDependencies(resources) + "\n"
	}

	issuesSection := SprintIssues(resources)

	intro := SectionStyle.Render(fmt.Sprintf("\nTesting %s ...\n", path))

	return fmt.Sprintf("%s%s%s%s\n%s\n", intro, depsSection, untestedSection, issuesSection, summary)
}

func SprintUntestedComponents(resources snykclient.Resources) string {
	result := fmt.Sprintf("\n" + SectionStyle.Render("Untested:") + "\n")

	for i := range resources.Untested {
		result += fmt.Sprintf("\n%s\n", RenderUntestedComponent(resources.Untested[i].BOMRef, resources.Untested[i].Reason))
	}

	return result
}

func SprintSummary(resources snykclient.Resources) string {
	return fmt.Sprintf("Tested %d dependencies for known issues, found %d.",
		len(resources.Tested),
		len(resources.Vulnerabilities),
	)
}

func SprintDependencies(resources snykclient.Resources) string {
	result := fmt.Sprintf("\n" + SectionStyle.Render("Packages:") + "\n")

	packages := make([]string, len(resources.Tested))
	_ = copy(packages, resources.Tested)

	slices.Sort(packages)

	for _, k := range packages {
		tmp := strings.SplitN(k, ":", 2)
		slices.Reverse(tmp)
		id := strings.SplitN(tmp[0], "?", 2)[0]

		result += SprintDependency(id, k)
	}

	return result
}

func SprintDependency(id, purl string) string {
	return fmt.Sprintf(`
  %s
  purl: %s
`, id, purl)
}

func SprintIssues(resources snykclient.Resources) string {
	result := fmt.Sprintf("\n" + SectionStyle.Render("Issues:") + "\n\n")

	vulns := SortVulns(resources.Vulnerabilities)

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

		result += SprintIssue(title, vulns[i].ID, introducedBy, severity)
	}

	return result
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
