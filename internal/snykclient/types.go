//nolint:tagliatelle // Allowing snake case for API response schemas
package snykclient

import (
	"fmt"
	"time"

	"github.com/snyk/cli-extension-sbom/internal/severities"
)

type SBOMTestResourceDocument struct {
	JSONAPI *JSONAPI          `json:"jsonapi"`
	Data    *SBOMTestResource `json:"data,omitempty"`
}

type SBOMTestResource struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type SBOMTestSummary struct {
	Tested               []string            `json:"tested"`
	Untested             []UntestedComponent `json:"untested"`
	TotalIssues          int                 `json:"total_issues"`
	TotalLicenseIssues   int                 `json:"total_license_issues"`
	TotalVulnerabilities int                 `json:"total_vulnerabilities"`

	VulnerabilitiesBySeverity struct {
		Critical int `json:"critical"`
		High     int `json:"high"`
		Medium   int `json:"medium"`
		Low      int `json:"low"`
	} `json:"vulnerabilities_by_severity"`
}

type UntestedComponent struct {
	BOMRef string `json:"bom_ref,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type SBOMTestRunAttributes struct {
	SBOM struct {
		SBOMFormat string `json:"format"`
	} `json:"sbom"`
	Summary SBOMTestSummary `json:"test_summary"`
}

type SBOMTestStatusResourceDocument struct {
	JSONAPI *JSONAPI                `json:"jsonapi"`
	Data    *SBOMTestStatusResource `json:"data,omitempty"`
}

type SBOMTestStatusResource struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		Status string `json:"status"`
	} `json:"attributes"`
}

type SBOMTestResultResourceDocument struct {
	JSONAPI  *JSONAPI                `json:"jsonapi"`
	Data     *SBOMTestResultResource `json:"data,omitempty"`
	Included []*IncludedResource     `json:"included,omitempty"`
}

type IncludedResource struct {
	Type string `json:"type"`
	ID   string `json:"id"`

	Relationships struct {
		AffectedPackage struct {
			Data struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			} `json:"data"`
		} `json:"affected_package"`
		Vulnerability struct {
			Data struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			} `json:"data"`
		} `json:"vulnerability"`
	} `json:"relationships,omitempty"`

	Attributes struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Purl    string `json:"purl"`

		IsFixable    bool  `json:"is_fixable"`
		UpgradePaths []any `json:"upgrade_paths"`

		Title       string    `json:"title"`
		Description string    `json:"description"`
		CreatedAt   time.Time `json:"created_at"`
		UpdatedAt   time.Time `json:"updated_at"`

		Problems []struct {
			ID     string `json:"id"`
			Source string `json:"source"`
		} `json:"problems"`

		Coordinates []struct {
			Remedies []struct {
				Description string `json:"description"`
				Details     struct {
					UpgradePackage string `json:"upgrade_package"`
				} `json:"details"`
				Type string `json:"type"`
			} `json:"remedies"`
			Representation []struct {
				ResourcePath string `json:"resource_path"`
			} `json:"representation"`
		} `json:"coordinates"`

		Severities []struct {
			Source string           `json:"source"`
			Level  severities.Level `json:"level"`
			Score  float64          `json:"score"`
			Vector string           `json:"vector"`
		} `json:"severities"`

		EffectiveSeverityLevel severities.Level `json:"effective_severity_level"`

		Slots []Slot `json:"slots"`
	} `json:"attributes,omitempty"`
}

type Slot struct {
	DisclosureTime  time.Time `json:"disclosure_time"`
	PublicationTime time.Time `json:"publication_time"`

	Exploit string `json:"exploit"`

	References []struct {
		URL   string `json:"url"`
		Title string `json:"title"`
	} `json:"references"`
}

type SBOMTestResultResource struct {
	ID            string                `json:"id"`
	Type          string                `json:"type"`
	Attributes    SBOMTestRunAttributes `json:"attributes"`
	Relationships struct {
		AffectedPkgs    RelationshipsData `json:"affected_pkgs"`
		Vulnerabilities RelationshipsData `json:"vulnerabilities"`
		Remedies        RelationshipsData `json:"remedies"`
	} `json:"relationships"`
}

type RelationshipsData struct {
	Data []struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"data"`
}

const (
	ResourceTypePackages        = "packages"
	ResourceTypeRemedies        = "remedies"
	ResourceTypeVulnerabilities = "vulnerabilities"
)

type Vulnerability struct {
	ID      string
	Name    string
	Version string
	PURL    string
	Title   string

	CreatedAt   time.Time
	ModifiedAt  time.Time
	DisclosedAt time.Time
	PublishedAt time.Time

	Exploit       string
	SeverityLevel severities.Level

	CWE, CVE  string
	CVSSv3    string
	CVSSscore float64
	SemVer    []string

	From        []string
	UpgradePath []any

	Packages []*Package
}

type Package struct {
	ID      string
	Name    string
	Version string
	PURL    string

	Vulnerabilities []*Vulnerability
}

type SBOMTestResult struct {
	Summary         *SBOMTestSummary
	Packages        map[string]*Package
	Vulnerabilities map[string]*Vulnerability
}

func (doc *SBOMTestResultResourceDocument) AsResult() *SBOMTestResult {
	r := SBOMTestResult{
		Summary:         &doc.Data.Attributes.Summary,
		Packages:        make(map[string]*Package),
		Vulnerabilities: make(map[string]*Vulnerability),
	}

	remedies := make([]*IncludedResource, 0)

	// extract all included resources
	for i, res := range doc.Included {
		switch res.Type {
		case ResourceTypePackages:
			r.Packages[res.ID] = &Package{
				ID:      res.ID,
				Name:    res.Attributes.Name,
				Version: res.Attributes.Version,
				PURL:    res.Attributes.Purl,
			}

		case ResourceTypeVulnerabilities:
			var slot Slot
			switch {
			case len(res.Attributes.Slots) == 1:
				slot = res.Attributes.Slots[0]

			case len(res.Attributes.Slots) > 1:
				// TODO(dekelund): handle this scenario
				panic(fmt.Sprintf("unexpected number of slots for %s", res.ID))
			}

			var cve, cwe string
			for i := range res.Attributes.Problems {
				switch res.Attributes.Problems[i].Source {
				case "CWE":
					cwe = res.Attributes.Problems[i].ID

				case "cve":
					cve = res.Attributes.Problems[i].ID
				}
			}

			var cvssScore float64
			var cvssV3 string

			for i := range res.Attributes.Severities {
				switch res.Attributes.Severities[i].Source {
				case "Snyk":
					cvssScore = res.Attributes.Severities[i].Score
					cvssV3 = res.Attributes.Severities[i].Vector
				default:
					break
				}
			}

			r.Vulnerabilities[res.ID] = &Vulnerability{
				ID: res.ID,

				Name:    res.Attributes.Name,
				Version: res.Attributes.Version,
				PURL:    res.Attributes.Purl,
				Title:   res.Attributes.Title,

				CreatedAt:  res.Attributes.CreatedAt,
				ModifiedAt: res.Attributes.UpdatedAt,

				DisclosedAt: slot.DisclosureTime,
				PublishedAt: slot.PublicationTime,

				Exploit: slot.Exploit,

				CVE: cve,
				CWE: cwe,

				CVSSv3:    cvssV3,
				CVSSscore: cvssScore,

				SeverityLevel: res.Attributes.EffectiveSeverityLevel,
			}

		case ResourceTypeRemedies:
			remedies = append(remedies, doc.Included[i])
		}
	}

	// connect packages and vulnerabilities
	for _, rem := range remedies {
		vuln, vok := r.Vulnerabilities[rem.Relationships.Vulnerability.Data.ID]
		pkg, pok := r.Packages[rem.Relationships.AffectedPackage.Data.ID]

		if !vok || !pok {
			continue
		}

		pkg.Vulnerabilities = append(pkg.Vulnerabilities, vuln)

		vuln.Packages = append(vuln.Packages, pkg)
		vuln.SemVer = append(vuln.SemVer, pkg.Version)
	}

	return &r
}
