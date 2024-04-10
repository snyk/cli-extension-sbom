//nolint:tagliatelle // Allowing snake case for API response schemas
package snykclient

import (
	"fmt"
	"time"
)

type SBOMTestResourceDocument struct {
	JSONAPI *JSONAPI `json:"jsonapi"`
	Data    struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"data,omitempty"`
}

type SBOMTestSummary struct {
	Tested                    []string            `json:"tested"`
	Untested                  []UntestedComponent `json:"untested"`
	TotalIssues               int                 `json:"total_issues"`
	TotalLicenseIssues        int                 `json:"total_license_issues"`
	TotalVulnerabilities      int                 `json:"total_vulnerabilities"`
	VulnerabilitiesBySeverity struct {
		Critical int `json:"critical"`
		High     int `json:"high"`
		Medium   int `json:"medium"`
		Low      int `json:"low"`
	} `json:"vulnerabilities_by_severity"`
}

type SBOMTestAttributes struct {
	SBOM struct {
		SBOMFormat string `json:"format"`
	} `json:"sbom"`
	Summary *SBOMTestSummary `json:"test_summary"`
}

type SBOMTestStatusResourceDocument struct {
	JSONAPI *JSONAPI                `json:"jsonapi,omitempty"`
	Data    *SBOMTestStatusResource `json:"data,omitempty"`
}

type SBOMTestStatusResource struct {
	ID         string                   `json:"id"`
	Type       string                   `json:"type"`
	Attributes SBOMTestStatusAttributes `json:"attributes"`
}

type SBOMTestStatusAttributes struct {
	Status string `json:"status"`
}

type SBOMTestResultResourceDocument struct {
	JSONAPI  *JSONAPI                 `json:"jsonapi,omitempty"`
	Data     *SBOMTestResultsResource `json:"data,omitempty"`
	Included []*IncludedResource      `json:"included,omitempty"`
}

const (
	ResourceTypePackages        = "packages"
	ResourceTypeRemedies        = "remedies"
	ResourceTypeVulnerabilities = "vulnerabilities"
)

func (doc *SBOMTestResultResourceDocument) AsUsable() *TheActualUsableThing {
	resources := TheActualUsableThing{
		Summary:         doc.Data.Attributes.Summary,
		Packages:        make(map[string]Package),
		Vulnerabilities: make(map[string]Vulnerability),
	}

	remedies := map[string][]string{}

	// extract all included resources
	for _, res := range doc.Included {
		switch res.Type {
		case ResourceTypePackages:
			resources.Packages[res.ID] = Package{
				ID:      res.ID,
				Name:    res.Attributes.Name,
				Version: res.Attributes.Version,
				PURL:    res.Attributes.Purl,
			}

		case ResourceTypeVulnerabilities:
			// doing something with a vuln here
			var slots Slots
			switch {
			case len(res.Attributes.Slots) == 1:
				slots = res.Attributes.Slots[0]

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

			resources.Vulnerabilities[res.ID] = Vulnerability{
				ID: res.ID,

				Name:    res.Attributes.Name,
				Version: res.Attributes.Version,
				PURL:    res.Attributes.Purl,
				Title:   res.Attributes.Title,

				CreatedAt:  res.Attributes.CreatedAt,
				ModifiedAt: res.Attributes.UpdatedAt,

				DisclosedAt: time.Time(slots.DisclosureTime),
				PublishedAt: time.Time(slots.PublicationTime),

				Exploit: slots.Exploit,

				CVE: cve,
				CWE: cwe,

				CVSSv3:    cvssV3,
				CVSSscore: cvssScore,

				SeverityLevel: res.Attributes.EffectiveSeverityLevel,
			}

		case ResourceTypeRemedies:
			pkgs := remedies[res.Relationships.Vulnerability.Data.ID]
			pkgs = append(pkgs, res.Relationships.AffectedPackage.Data.ID)
			remedies[res.Relationships.Vulnerability.Data.ID] = pkgs
		}
	}

	for vulnID, pkgs := range remedies {
		vuln := resources.Vulnerabilities[vulnID]
		for _, pkgID := range pkgs {
			pkg := resources.Packages[pkgID]

			pkg.Vulnerabilities = append(pkg.Vulnerabilities, &vuln)
			vuln.Packages = append(vuln.Packages, &pkg)

			vuln.SemVer = append(vuln.SemVer, pkg.Version)

			resources.Packages[pkgID] = pkg
			resources.Vulnerabilities[vulnID] = vuln
		}
	}

	return &resources
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

type SBOMTestResultsResource struct {
	ID            string                      `json:"id"`
	Type          string                      `json:"type"`
	Attributes    SBOMTestAttributes          `json:"attributes"`
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

type Vulnerability struct {
	ID, Name, Version, PURL string

	Title    string
	Packages []*Package

	CreatedAt   time.Time
	DisclosedAt time.Time
	PublishedAt time.Time
	ModifiedAt  time.Time

	Exploit string

	CWE, CVE  string
	CVSSv3    string
	CVSSscore float64
	SemVer    []string

	From        []string
	UpgradePath []any

	SeverityLevel SeverityLevel
}

type Package struct {
	ID              string
	Name            string
	Version         string
	PURL            string
	Vulnerabilities []*Vulnerability
}

type UntestedComponent struct {
	BOMRef string
	Reason string
}

type Resources struct {
	Tested          []string
	Untested        []UntestedComponent
	Packages        map[string]Package
	Vulnerabilities map[string]Vulnerability
}

type TheActualUsableThing struct {
	Summary         *SBOMTestSummary
	Packages        map[string]Package
	Vulnerabilities map[string]Vulnerability
}

// ToResources maps the JSON:API data to more usable data structures.
//
// Deprecated: Use SBOMTestResultResource.ToUsable() instead.
func ToResources(tested []string, untested []UntestedComponent, includes []*IncludedResource) Resources {
	resources := Resources{
		Tested:          make([]string, len(tested)),
		Untested:        make([]UntestedComponent, len(untested)),
		Packages:        make(map[string]Package),
		Vulnerabilities: make(map[string]Vulnerability),
	}

	_ = copy(resources.Tested, tested)

	for i, uc := range untested {
		resources.Untested[i] = UntestedComponent(uc)
	}

	remedies := map[string][]string{}

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
		case ResourceTypePackages:
			resources.Packages[val.ID] = Package{
				ID:      val.ID,
				Name:    val.Attributes.Name,
				Version: val.Attributes.Version,
				PURL:    val.Attributes.Purl,
			}

		case ResourceTypeVulnerabilities:
			var cve, cwe string

			for i := range val.Attributes.Problems {
				switch val.Attributes.Problems[i].Source {
				case "CWE":
					cwe = val.Attributes.Problems[i].ID

				case "cve":
					cve = val.Attributes.Problems[i].ID
				}
			}

			var cvssScore float64
			var cvssV3 string

			for i := range val.Attributes.Severities {
				switch val.Attributes.Severities[i].Source {
				case "Snyk":
					cvssScore = val.Attributes.Severities[i].Score
					cvssV3 = val.Attributes.Severities[i].Vector
				default:
					break
				}
			}

			resources.Vulnerabilities[val.ID] = Vulnerability{
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

				CVSSv3:    cvssV3,
				CVSSscore: cvssScore,

				SeverityLevel: val.Attributes.EffectiveSeverityLevel,
			}

		case ResourceTypeRemedies:
			pkgs := remedies[val.Relationships.Vulnerability.Data.ID]
			pkgs = append(pkgs, val.Relationships.AffectedPackage.Data.ID)
			remedies[val.Relationships.Vulnerability.Data.ID] = pkgs
		}
	}

	for vulnID, pkgs := range remedies {
		vuln := resources.Vulnerabilities[vulnID]
		for _, pkgID := range pkgs {
			pkg := resources.Packages[pkgID]

			pkg.Vulnerabilities = append(pkg.Vulnerabilities, &vuln)
			vuln.Packages = append(vuln.Packages, &pkg)

			vuln.SemVer = append(vuln.SemVer, pkg.Version)

			resources.Packages[pkgID] = pkg
			resources.Vulnerabilities[vulnID] = vuln
		}
	}

	return resources
}
