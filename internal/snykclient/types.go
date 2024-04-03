//nolint:tagliatelle // Allowing snake case for API response schemas
package snykclient

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

type GetSBOMTestStatusResponseBody struct {
	JSONAPI *JSONAPI                       `json:"jsonapi,omitempty"`
	Data    *GetSBOMTestStatusResponseData `json:"data,omitempty"`
}

type GetSBOMTestStatusResponseData struct {
	ID         string                   `json:"id"`
	Type       string                   `json:"type"`
	Attributes SBOMTestStatusAttributes `json:"attributes"`
}

type SBOMTestStatusAttributes struct {
	Status string `json:"status"`
}

type GetSBOMTestResultResponseBody struct {
	JSONAPI  *JSONAPI                       `json:"jsonapi,omitempty"`
	Data     *GetSBOMTestResultResponseData `json:"data,omitempty"`
	Included *Includes                      `json:"included,omitempty"`
}

type Includes []interface{} // List of packages and vulnerabilities

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
