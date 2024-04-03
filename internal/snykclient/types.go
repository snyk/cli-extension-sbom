//nolint:tagliatelle // Allowing snake case for API response schemas
package snykclient

import (
	"strings"
	"time"

	"golang.org/x/exp/slices"
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

type SeverityLevel string

func (l SeverityLevel) String() string {
	return string(l)
}

const (
	LowSeverity      = SeverityLevel("low")
	MediumSeverity   = SeverityLevel("medium")
	HighSeverity     = SeverityLevel("high")
	CriticalSeverity = SeverityLevel("critical")
)

func CmpSeverityLevel(a, b SeverityLevel) int {
	a = SeverityLevel(strings.ToLower(string(a)))
	b = SeverityLevel(strings.ToLower(string(b)))

	if a == b {
		return 0
	}

	switch {
	case a == LowSeverity:
		return -1

	case b == LowSeverity:
		return 1

	case a == MediumSeverity:
		return -1

	case b == MediumSeverity:
		return 1

	case a == HighSeverity:
		return -1

	case b == HighSeverity:
		return 1

	case a == CriticalSeverity:
		return -1

	case b == CriticalSeverity:
		return 1
	}

	return 0
}

type SortedView struct {
	Packages, Remedies, Vulnerabilities []*Includes
	Relationship                        map[string]string
}

const (
	Packages        = "packages"
	Remedies        = "remedies"
	Vulnerabilities = "vulnerabilities"
)

func SortIncludes(i []*Includes) SortedView {
	slices.SortFunc(i, cmpIncludes)

	var p, r, v int

	relationship := map[string]string{}

	// NOTE(dekelund): Remedies must have higher precedence than
	// vulnerabilities in snykclient.CmpIncludes for this to
	// work.
	for _, val := range i {
		switch val.Type {
		case Packages:
			p++
			r++
			v++

		case Remedies:
			r++
			v++
			relationship[val.Relationships.Vulnerability.Data.ID] = val.Relationships.AffectedPackage.Data.ID

		case Vulnerabilities:
			v++
		}
	}

	return SortedView{
		Packages:        i[:p],
		Remedies:        i[p:r],
		Vulnerabilities: i[r:v],
		Relationship:    relationship,
	}
}

func cmpIncludes(a, b *Includes) int {
	// NOTE(dekelund): SortIncludes relays on the order to compute
	// the relationship between packages and vulnerabilities.
	switch {
	case a.Type == b.Type:
		return CmpSeverityLevel(a.Attributes.EffectiveSeverityLevel, b.Attributes.EffectiveSeverityLevel)

	case a.Type == Packages:
		return -1

	case b.Type == Packages:
		return 1

	case a.Type == Remedies:
		return -1

	case b.Type == Remedies:
		return 1

	case a.Type == Vulnerabilities:
		return -1

	case b.Type == Vulnerabilities:
		return 1
	}

	return 0
}

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

		Slots []struct {
			DisclosureTime  string `json:"disclosure_time"`
			Exploit         string `json:"exploit"`
			PublicationTime string `json:"publication_time"`
			References      []struct {
				URL   string `json:"url"`
				Title string `json:"title"`
			} `json:"references"`
		} `json:"slots"`
	} `json:"attributes,omitempty"`
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
