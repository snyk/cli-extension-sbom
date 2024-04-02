//nolint:tagliatelle // Allowing snake case for API response schemas
package snykclient

import "time"

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
	Included *Includes                      `json:"included,omitempty"`
}

type Includes []interface{} // List of packages and vulnerabilities

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
		Source string  `json:"source"`
		Level  string  `json:"level"`
		Score  float32 `json:"score"`
		Vector string  `json:"vector"`
	} `json:"severities"`
	EffectiveSeverityLevel string `json:"effective_severity_level"`
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
