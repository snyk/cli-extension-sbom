package sbomtest

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/snyk/cli-extension-sbom/internal/snykclient"
)

type (
	JSONOutput struct {
		OK              bool            `json:"ok"`
		DependencyCount int             `json:"dependencyCount"`
		UniqueCount     int             `json:"uniqueCount"`
		Summary         string          `json:"summary"`
		Remediation     interface{}     `json:"remediation,omitempty"`
		Filtered        interface{}     `json:"filtered,omitempty"`
		Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	}

	Vulnerability struct {
		CreationTime         time.Time  `json:"creationTime,omitempty"`
		DisclosureTime       time.Time  `json:"disclosureTime,omitempty"`
		Exploit              string     `json:"exploit,omitempty"`
		ID                   string     `json:"id,omitempty"`
		Identifiers          Identifier `json:"identifiers,omitempty"`
		ModificationTime     time.Time  `json:"modificationTime,omitempty"`
		PackageName          string     `json:"packageName,omitempty"`
		PublicationTime      time.Time  `json:"publicationTime,omitempty"`
		SemVer               SemVer     `json:"semver,omitempty"`
		Severity             string     `json:"severity,omitempty"`
		SeverityWithCritical string     `json:"severityWithCritical,omitempty"`
		Title                string     `json:"title,omitempty"`
		Version              string     `json:"version,omitempty"`
		Name                 string     `json:"name,omitempty"`
		CVSSv3               string     `json:"CVSSv3,omitempty"`
		CVSSScore            float64    `json:"cvssScore,omitempty"`
	}

	Identifier struct {
		CVE []string `json:"CVE,omitempty"`
		CWE []string `json:"CWE,omitempty"`
	}

	SemVer struct {
		Vulnerable []string `json:"Vulnerable,omitempty"`
	}
)

func asJSON(result *snykclient.GetSBOMTestResultResponseBody) (data []byte, contentType string, err error) {
	contentType = MIMETypeJSON

	jsonOutput, err := resultToJSONOutput(result)
	if err != nil {
		return nil, contentType, err
	}

	data, err = json.Marshal(jsonOutput)
	if err != nil {
		return nil, contentType, err
	}

	return data, contentType, nil
}

func resultToJSONOutput(body *snykclient.GetSBOMTestResultResponseBody) (JSONOutput, error) {
	resources := snykclient.ToResources(
		body.Data.Attributes.Summary.Tested,
		body.Data.Attributes.Summary.Untested,
		body.Included,
	)

	vulns := make([]Vulnerability, 0, len(resources.Tested)+len(resources.Untested))

	sortedVulns := SortVulns(resources.Vulnerabilities)

	for i := range sortedVulns {
		severityWithoutCritical := sortedVulns[i].SeverityLevel

		if severityWithoutCritical == snykclient.CriticalSeverity {
			severityWithoutCritical = snykclient.HighSeverity
		}

		var cve, cwe []string

		if sortedVulns[i].CVE != "" {
			cve = append(cve, sortedVulns[i].CVE)
		}

		if sortedVulns[i].CWE != "" {
			cve = append(cve, sortedVulns[i].CWE)
		}

		for pid := range sortedVulns[i].Packages {
			packages := sortedVulns[i].Packages

			vulns = append(vulns, Vulnerability{
				ID:          sortedVulns[i].ID,
				PackageName: packages[pid].Name,
				Name:        packages[pid].Name,
				Version:     packages[pid].Version,

				Title: sortedVulns[i].Title,

				CreationTime:     sortedVulns[i].CreatedAt,
				PublicationTime:  sortedVulns[i].PublishedAt,
				DisclosureTime:   sortedVulns[i].DisclosedAt,
				ModificationTime: sortedVulns[i].ModifiedAt,

				Exploit: sortedVulns[i].Exploit,

				Identifiers: Identifier{
					CVE: cve,
					CWE: cwe,
				},

				SemVer: SemVer{
					Vulnerable: sortedVulns[i].SemVer,
				},

				CVSSv3:    sortedVulns[i].CVSSv3,
				CVSSScore: sortedVulns[i].CVSSscore,

				Severity:             severityWithoutCritical.String(),
				SeverityWithCritical: sortedVulns[i].SeverityLevel.String(),
			})
		}
	}

	return JSONOutput{
		OK:              len(resources.Vulnerabilities) == 0,
		DependencyCount: len(resources.Tested) + len(resources.Untested),
		UniqueCount:     133, // what is this??
		Summary:         fmt.Sprintf("Found %d vulnerabilities", len(resources.Vulnerabilities)),
		Vulnerabilities: vulns,
	}, nil
}
