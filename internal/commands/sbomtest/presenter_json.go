package sbomtest

import (
	"encoding/json"
	"fmt"

	"github.com/snyk/cli-extension-sbom/internal/snykclient"
)

type (
	JSONOutput struct {
		OK              bool             `json:"ok"`
		DependencyCount int              `json:"dependencyCount"`
		UniqueCount     int              `json:"uniqueCount"`
		Summary         string           `json:"summary"`
		Remediation     interface{}      `json:"remediation,omitempty"`
		Filtered        interface{}      `json:"filtered,omitempty"`
		Vulnerabilities []*Vulnerability `json:"vulnerabilities"`
	}

	Vulnerability struct {
		ID    string
		Title string
	}
)

func asJSON(result *snykclient.GetSBOMTestResultResponseBody) (data []byte, contentType string, err error) {
	contentType = MIMETypeJSON

	data, err = json.Marshal(resultToJSONOutput(result))
	if err != nil {
		return nil, contentType, err
	}

	return data, contentType, nil
}

func resultToJSONOutput(body *snykclient.GetSBOMTestResultResponseBody) JSONOutput {
	vulns := make([]*Vulnerability, 0)
	res := body.Data.Attributes

	return JSONOutput{
		OK:              res.Summary.TotalIssues == 0,
		DependencyCount: len(res.Summary.Tested) + len(res.Summary.Untested),
		UniqueCount:     133, // what is this??
		Summary:         fmt.Sprintf("Found %d vulnerabilities", res.Summary.TotalVulnerabilities),
		Vulnerabilities: vulns,
	}
}
