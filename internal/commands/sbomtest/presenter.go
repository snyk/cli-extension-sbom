//nolint:tagliatelle // Disabling for snake-case in JSON payloads.
package sbomtest

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"golang.org/x/exp/slices"

	"github.com/snyk/cli-extension-sbom/internal/severities"
	"github.com/snyk/cli-extension-sbom/internal/snykclient"
	"github.com/snyk/cli-extension-sbom/internal/view"
)

type (
	JSONOutput struct {
		OK              bool            `json:"ok"`
		DependencyCount int             `json:"dependencyCount"`
		Summary         string          `json:"summary"`
		Remediation     interface{}     `json:"remediation,omitempty"`
		Filtered        interface{}     `json:"filtered,omitempty"`
		Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	}

	Vulnerability struct {
		CreationTime         time.Time        `json:"creationTime,omitempty"`
		DisclosureTime       time.Time        `json:"disclosureTime,omitempty"`
		Exploit              string           `json:"exploit,omitempty"`
		ID                   string           `json:"id,omitempty"`
		Identifiers          Identifier       `json:"identifiers,omitempty"`
		ModificationTime     time.Time        `json:"modificationTime,omitempty"`
		PackageName          string           `json:"packageName,omitempty"`
		PublicationTime      time.Time        `json:"publicationTime,omitempty"`
		SemVer               SemVer           `json:"semver,omitempty"`
		Severity             severities.Level `json:"severity,omitempty"`
		SeverityWithCritical severities.Level `json:"severityWithCritical,omitempty"`
		Title                string           `json:"title,omitempty"`
		Version              string           `json:"version,omitempty"`
		Name                 string           `json:"name,omitempty"`
		CVSSv3               string           `json:"CVSSv3,omitempty"`
		CVSSScore            float64          `json:"cvssScore,omitempty"`
	}

	Identifier struct {
		CVE []string `json:"CVE,omitempty"`
		CWE []string `json:"CWE,omitempty"`
	}

	SemVer struct {
		Vulnerable []string `json:"Vulnerable,omitempty"`
	}
)

func resultToJSONOutput(res *snykclient.SBOMTestResult) JSONOutput {
	vulns := make([]Vulnerability, 0, len(res.Vulnerabilities))

	for _, vuln := range res.Vulnerabilities {
		var cve, cwe []string

		if vuln.CVE != "" {
			cve = append(cve, vuln.CVE)
		}

		if vuln.CWE != "" {
			cwe = append(cwe, vuln.CWE)
		}

		for pid := range vuln.Packages {
			packages := vuln.Packages

			vulns = append(vulns, Vulnerability{
				ID:          vuln.ID,
				PackageName: packages[pid].Name,
				Name:        packages[pid].Name,
				Version:     packages[pid].Version,

				Title: vuln.Title,

				CreationTime:     vuln.CreatedAt,
				PublicationTime:  vuln.PublishedAt,
				DisclosureTime:   vuln.DisclosedAt,
				ModificationTime: vuln.ModifiedAt,

				Exploit: vuln.Exploit,

				Identifiers: Identifier{
					CVE: cve,
					CWE: cwe,
				},

				SemVer: SemVer{
					Vulnerable: vuln.SemVer,
				},

				CVSSv3:    vuln.CVSSv3,
				CVSSScore: vuln.CVSSscore,

				Severity:             vuln.SeverityLevel,
				SeverityWithCritical: vuln.SeverityLevel,
			})
		}
	}

	sortIssues(vulns)

	return JSONOutput{
		OK:              res.Summary.TotalIssues == 0,
		DependencyCount: len(res.Summary.Tested) + len(res.Summary.Untested),
		Summary:         fmt.Sprintf("Found %d vulnerabilities", len(res.Vulnerabilities)),
		Vulnerabilities: vulns,
	}
}

const (
	MIMETypeJSON = "application/json"
	MIMETypeText = "text/plain"
)

func RenderJSONResult(w io.Writer, res *snykclient.SBOMTestResult) error {
	return json.NewEncoder(w).Encode(resultToJSONOutput(res))
}

func RenderPrettyResult(w io.Writer, orgID, filepath string, res *snykclient.SBOMTestResult) error {
	issues := make([]view.OpenIssue, 0, len(res.Vulnerabilities))
	untested := make([]view.Component, 0, len(res.Summary.Untested))

	for i := range res.Vulnerabilities {
		introducedBy := make([]view.IntroducedBy, 0, len(res.Vulnerabilities[i].Packages))
		for _, pkg := range res.Vulnerabilities[i].Packages {
			introducedBy = append(introducedBy, view.IntroducedBy{
				Name:    pkg.Name,
				Version: pkg.Version,
				PURL:    pkg.PURL,
			})
		}

		issues = append(issues, view.OpenIssue{
			Description:  res.Vulnerabilities[i].Title,
			Severity:     res.Vulnerabilities[i].SeverityLevel,
			SnykRef:      res.Vulnerabilities[i].ID,
			IntroducedBy: introducedBy,
		})
	}

	for i := range res.Summary.Untested {
		untested = append(untested, view.Component{
			Reference: res.Summary.Untested[i].BOMRef,
			Info:      res.Summary.Untested[i].Reason,
		})
	}

	p := &view.Presentation{
		Org:  orgID,
		Path: filepath,
		Summary: view.Summary{
			TotalIssues: res.Summary.TotalIssues,
			Critical:    res.Summary.VulnerabilitiesBySeverity.Critical,
			High:        res.Summary.VulnerabilitiesBySeverity.High,
			Medium:      res.Summary.VulnerabilitiesBySeverity.Medium,
			Low:         res.Summary.VulnerabilitiesBySeverity.Low,
		},
		Issues:   issues,
		Untested: untested,
	}

	_, err := view.Render(w, p)

	return err
}

func sortIssues(vulns []Vulnerability) {
	slices.SortFunc(vulns, func(a, b Vulnerability) int {
		if a.Severity != b.Severity {
			return int(a.Severity - b.Severity)
		}

		if a.ID < b.ID {
			return -1
		}

		if a.ID > b.ID {
			return +1
		}

		if a.PackageName < b.PackageName {
			return -1
		}

		if a.PackageName > b.PackageName {
			return +1
		}

		if a.Version < b.Version {
			return -1
		}

		if a.Version > b.Version {
			return +1
		}

		return 0
	})
}
