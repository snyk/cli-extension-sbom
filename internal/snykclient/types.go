//nolint:tagliatelle // Allowing snake case for API response schemas
package snykclient

import (
	"encoding/json"
	"fmt"
	"time"
)

type CreateSBOMTestRunResponseBody struct {
	JSONAPI *JSONAPI                       `json:"jsonapi,omitempty"`
	Data    *CreateSBOMTestRunResponseData `json:"data,omitempty"`
}

type CreateSBOMTestRunResponseData struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type SBOMTestRunSummary struct {
	Tested                    []string                  `json:"tested"`
	Untested                  []UnsupportedComponent    `json:"untested"`
	TotalIssues               int                       `json:"total_issues"`
	TotalLicenseIssues        int                       `json:"total_license_issues"`
	TotalVulnerabilities      int                       `json:"total_vulnerabilities"`
	VulnerabilitiesBySeverity VulnerabilitiesBySeverity `json:"vulnerabilities_by_severity"`
}

type UnsupportedComponent struct {
	BOMRef string `json:"bom_ref,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type VulnerabilitiesBySeverity struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

type SBOMMetaData struct {
	SBOMFormat string `json:"format"`
}

type SBOMTestRunAttributes struct {
	SBOM    SBOMMetaData       `json:"sbom"`
	Summary SBOMTestRunSummary `json:"test_summary"`
}

type GetSBOMTestResultResponseBody struct {
	JSONAPI  *JSONAPI                       `json:"jsonapi,omitempty"`
	Data     *GetSBOMTestResultResponseData `json:"data,omitempty"`
	Included []*Includes                    `json:"included,omitempty"`
}

type SeverityLevel int

func (l SeverityLevel) String() string {
	switch l {
	default:
		return ""
	case LowSeverity:
		return "LOW"
	case MediumSeverity:
		return "MEDIUM"
	case HighSeverity:
		return "HIGH"
	case CriticalSeverity:
		return "CRITICAL"
	}
}

func (l *SeverityLevel) UnmarshalJSON(b []byte) error {
	var sev string
	if err := json.Unmarshal(b, &sev); err != nil {
		return err
	}

	switch sev {
	default:
		return fmt.Errorf("invalid severity level: %s", sev)
	case "low":
		*l = LowSeverity
	case "medium":
		*l = MediumSeverity
	case "high":
		*l = HighSeverity
	case "critical":
		*l = CriticalSeverity
	}

	return nil
}

const (
	LowSeverity SeverityLevel = iota
	MediumSeverity
	HighSeverity
	CriticalSeverity
)

type SortedView struct {
	Packages, Remedies, Vulnerabilities []*Includes
	Relationship                        map[string]string
}

const (
	Packages        = "packages"
	Remedies        = "remedies"
	Vulnerabilities = "vulnerabilities"
)

type Includes struct {
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
			Source string        `json:"source"`
			Level  SeverityLevel `json:"level"`
			Score  float64       `json:"score"`
			Vector string        `json:"vector"`
		} `json:"severities"`

		EffectiveSeverityLevel SeverityLevel `json:"effective_severity_level"`

		Slots []Slots `json:"slots"`
	} `json:"attributes,omitempty"`
}

type Slots struct {
	DisclosureTime  SBOMTime `json:"disclosure_time"`
	PublicationTime SBOMTime `json:"publication_time"`

	Exploit string `json:"exploit"`

	References []struct {
		URL   string `json:"url"`
		Title string `json:"title"`
	} `json:"references"`
}

type Vulnerability struct {
	ID         string                  `json:"id"`
	Type       string                  `json:"type"`
	Attributes VulnerabilityAttributes `json:"attributes"`
}

type VulnerabilityAttributes struct {
	Title       string    `json:"title"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Problems    []struct {
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
		Source string        `json:"source"`
		Level  SeverityLevel `json:"level"`
		Score  float32       `json:"score"`
		Vector string        `json:"vector"`
	} `json:"severities"`
	EffectiveSeverityLevel SeverityLevel `json:"effective_severity_level"`
	Slots                  []struct {
		DisclosureTime  time.Time `json:"disclosure_time"`
		PublicationTime time.Time `json:"publication_time"`
	} `json:"slots"`
}

type GetSBOMTestResultResponseData struct {
	ID            string                      `json:"id"`
	Type          string                      `json:"type"`
	Attributes    SBOMTestRunAttributes       `json:"attributes"`
	Relationships SBOMTestResultRelationships `json:"relationships"`
}

type SBOMTestResultRelationships struct {
	AffectedPkgs    RelationshipsData `json:"affected_pkgs"`
	Vulnerabilities RelationshipsData `json:"vulnerabilities"`
	Remedies        RelationshipsData `json:"remedies"`
}

type RelationshipData struct {
	Data ResourceReference `json:"data"`
}

type RelationshipsData struct {
	Data []ResourceReference `json:"data"`
}

type ResourceReference struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type SBOMTime time.Time

func (t *SBOMTime) UnmarshalJSON(b []byte) error {
	tmp, err := time.Parse("\"2006-01-02 15:04:05 +0000 UTC\"", string(b))
	if err != nil {
		return err
	}

	*t = SBOMTime(tmp)

	return nil
}

type VulnerabilityResource struct {
	ID, Name, Version, PURL string

	Title    string
	Packages []*PackageResource

	CreatedAt   time.Time
	DisclosedAt time.Time
	PublishedAt time.Time
	ModifiedAt  time.Time

	Exploit string

	CWE, CVE string
	SemVer   []string

	From        []string
	UpgradePath []any

	SeverityLevel SeverityLevel
}

type PackageResource struct {
	ID, Name, Version, PURL string
	Vulnerabilities         []*VulnerabilityResource
}

type UnsupportedComponentResource struct {
	BOMRef string
	Reason string
}

type Resources struct {
	Tested          []string
	Untested        []UnsupportedComponentResource
	Packages        map[string]PackageResource
	Vulnerabilities map[string]VulnerabilityResource
}

func ToResources(tested []string, untested []UnsupportedComponent, includes []*Includes) Resources {
	resources := Resources{
		Tested:          make([]string, len(tested)),
		Untested:        make([]UnsupportedComponentResource, len(untested)),
		Packages:        make(map[string]PackageResource),
		Vulnerabilities: make(map[string]VulnerabilityResource),
	}

	_ = copy(resources.Tested, tested)

	for i, uc := range untested {
		resources.Untested[i] = UnsupportedComponentResource(uc)
	}

	remedies := map[string]string{}

	for _, val := range includes {
		var slots Slots

		switch {
		case len(val.Attributes.Slots) == 1:
			slots = val.Attributes.Slots[0]

		case len(val.Attributes.Slots) > 1:
			// TODO(dekelund): handle this scenario
			panic(fmt.Sprintf("unexpected number of slots for %s", val.ID))
		}

		switch val.Type {
		case Packages:
			resources.Packages[val.ID] = PackageResource{
				ID:      val.ID,
				Name:    val.Attributes.Name,
				Version: val.Attributes.Version,
				PURL:    val.Attributes.Purl,
			}

		case Vulnerabilities:
			var cve, cwe string

			for i := range val.Attributes.Problems {
				switch val.Attributes.Problems[i].Source {
				case "CWE":
					cwe = val.Attributes.Problems[i].ID

				case "cve":
					cve = val.Attributes.Problems[i].ID
				}
			}

			resources.Vulnerabilities[val.ID] = VulnerabilityResource{
				ID: val.ID,

				Name:    val.Attributes.Name,
				Version: val.Attributes.Version,
				PURL:    val.Attributes.Purl,
				Title:   val.Attributes.Title,

				CreatedAt:  val.Attributes.CreatedAt,
				ModifiedAt: val.Attributes.UpdatedAt,

				DisclosedAt: time.Time(slots.DisclosureTime),
				PublishedAt: time.Time(slots.PublicationTime),

				Exploit: slots.Exploit,

				CVE: cve,
				CWE: cwe,

				SeverityLevel: val.Attributes.EffectiveSeverityLevel,
			}

		case Remedies:
			// TODO(dekelund): consider one to many relationship.
			remedies[val.Relationships.Vulnerability.Data.ID] = val.Relationships.AffectedPackage.Data.ID
		}
	}

	for vulnID, pkgID := range remedies {
		pkg := resources.Packages[pkgID]
		vuln := resources.Vulnerabilities[vulnID]

		pkg.Vulnerabilities = append(pkg.Vulnerabilities, &vuln)
		vuln.Packages = append(vuln.Packages, &pkg)

		vuln.SemVer = append(vuln.SemVer, pkg.Version)

		resources.Packages[pkgID] = pkg
		resources.Vulnerabilities[vulnID] = vuln
	}

	return resources
}
