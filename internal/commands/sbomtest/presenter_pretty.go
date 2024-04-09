package sbomtest

import (
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/exp/slices"

	"github.com/snyk/cli-extension-sbom/internal/snykclient"
)

func renderPrettyResult(path string, body *snykclient.GetSBOMTestResultResponseBody, printDeps bool, org string) (data []byte, contentType string, err error) {
	resources := snykclient.ToResources(
		body.Data.Attributes.Summary.Tested,
		body.Data.Attributes.Summary.Untested,
		body.Included,
	)

	output := AsHumanReadable(path, resources, printDeps, org, body.Data.Attributes.Summary)

	return []byte(output), MIMETypeText, nil
}

func AsHumanReadable(path string, resources snykclient.Resources, printDeps bool, org string, sum snykclient.SBOMTestRunSummary) string {
	intro := SprintIntro(path)

	summary := SprintSummary(resources, org, path, sum)

	var untestedSection string
	if len(resources.Untested) > 0 {
		untestedSection = SprintUntestedComponents(resources) + "\n"
	}

	if len(resources.Tested) == 0 {
		return fmt.Sprintf("%s%s%s\n\n", intro, untestedSection, summary)
	}

	var depsSection string

	if printDeps {
		depsSection = SprintDependencies(resources) + "\n"
	}

	issuesSection := SprintIssues(resources)
	return fmt.Sprintf("%s%s%s%s\n%s\n", intro, depsSection, untestedSection, issuesSection, summary)
}

func SprintIntro(filepath string) string {
	return SectionStyle.Render(fmt.Sprintf("\nTesting %s ...\n", filepath))
}

func SprintUntestedComponents(resources snykclient.Resources) string {
	result := fmt.Sprintf("\n" + SectionStyle.Render("Untested:") + "\n")

	for i := range resources.Untested {
		result += fmt.Sprintf("\n%s\n", RenderUntestedComponent(resources.Untested[i].BOMRef, resources.Untested[i].Reason))
	}

	return fmt.Sprintf(`%s
-------------------------------------------------------`, result)
}

func SprintSummary(resources snykclient.Resources, org, filepath string, sum snykclient.SBOMTestRunSummary) string {
	var out string

	theIssues := fmt.Sprintf("%d [ ", sum.TotalIssues)
	if sum.VulnerabilitiesBySeverity.Critical > 0 {
		theIssues += criticalStyle.Render(fmt.Sprintf("%d %s", sum.VulnerabilitiesBySeverity.Critical, snykclient.CriticalSeverity))
	}
	if sum.VulnerabilitiesBySeverity.High > 0 {
		theIssues += highStyle.Render(fmt.Sprintf("  %d %s", sum.VulnerabilitiesBySeverity.High, snykclient.HighSeverity))
	}
	if sum.VulnerabilitiesBySeverity.Medium > 0 {
		theIssues += mediumStyle.Render(fmt.Sprintf("  %d %s", sum.VulnerabilitiesBySeverity.Medium, snykclient.MediumSeverity))
	}
	if sum.VulnerabilitiesBySeverity.Low > 0 {
		theIssues += lowStyle.Render(fmt.Sprintf("  %d %s", sum.VulnerabilitiesBySeverity.Low, snykclient.LowSeverity))
	}

	theIssues += " ]"

	out += SectionStyle.Render("Test summary")
	out += "\n\n"
	out += fmt.Sprintf("  %-15s %s\n", "Organization:", org)
	out += fmt.Sprintf("  %-15s %s\n", "Test type:", "Software Bill of Materials")
	out += fmt.Sprintf("  %-15s %s\n", "Path:", filepath)
	out += "\n"
	out += fmt.Sprintf("  %-15s %s\n", "Open issues:", theIssues)

	return out
}

func SprintDependencies(resources snykclient.Resources) string {
	result := fmt.Sprintf("\n" + SectionStyle.Render("Packages:") + "\n")

	packages := make([]string, len(resources.Tested))
	_ = copy(packages, resources.Tested)

	slices.Sort(packages)

	for _, purl := range packages {
		result += SprintDependency(purl)
	}

	return result
}

var regexPurl = regexp.MustCompile(`^pkg:([^@?#]+)(@([^\?#]+))?(\?.+)?$`)

func SprintDependency(purl string) string {
	pkgId := purl

	if m := regexPurl.FindStringSubmatch(purl); len(m) > 1 {
		fullname := m[1]
		version := ""
		if len(m) > 2 {
			version = m[2]
		}
		parts := strings.Split(fullname, "/")
		parts[len(parts)-1] = SectionStyle.Render(parts[len(parts)-1])

		pkgId = strings.Join(parts, "/") + version
	}

	return fmt.Sprintf(`
  %s
  purl: %s
`, pkgId, purl)
}

func SprintIssues(resources snykclient.Resources) string {
	result := fmt.Sprintf("\n" + SectionStyle.Render("Open issues:") + "\n\n")

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

		if a.Packages[0].ID < b.Packages[0].ID {
			return -1
		}

		if a.Packages[0].ID > b.Packages[0].ID {
			return +1
		}

		return 0
	})

	return result
}
