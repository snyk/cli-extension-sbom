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

	for id, vuln := range resources.Vulnerabilities {
		severityWithoutCritical := vuln.SeverityLevel

		if severityWithoutCritical == snykclient.CriticalSeverity {
			severityWithoutCritical = snykclient.HighSeverity
		}

		var cve, cwe []string

		if vuln.CVE != "" {
			cve = append(cve, vuln.CVE)
		}

		if vuln.CWE != "" {
			cve = append(cve, vuln.CWE)
		}

		for pid, pkg := range resources.Vulnerabilities {
			vulns = append(vulns, Vulnerability{
				CreationTime:     vuln.CreatedAt,
				PublicationTime:  vuln.PublishedAt,
				DisclosureTime:   vuln.DisclosedAt,
				ModificationTime: vuln.ModifiedAt,
				Exploit:          vuln.Exploit,
				ID:               id,
				Identifiers: Identifier{
					CVE: cve,
					CWE: cwe,
				},
				PackageName: pid,
				SemVer: SemVer{
					Vulnerable: vuln.SemVer,
				},
				Severity:             severityWithoutCritical.String(),
				SeverityWithCritical: vuln.SeverityLevel.String(),
				Title:                pkg.Title,
				Version:              pkg.Version,
				Name:                 pkg.Name,
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
