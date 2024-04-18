package sbomtest

import (
	"encoding/json"

	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"

	"github.com/snyk/cli-extension-sbom/internal/snykclient"
)

func BuildTestSummary(resultsSummary *snykclient.SBOMTestSummary) (data []byte, contentType string, err error) {
	summary := json_schemas.TestSummary{
		Type: "sbom",
		Results: []json_schemas.TestSummaryResult{
			{
				Severity: "critical",
				Total:    resultsSummary.VulnerabilitiesBySeverity.Critical,
				Open:     resultsSummary.VulnerabilitiesBySeverity.Critical,
			},
			{
				Severity: "high",
				Total:    resultsSummary.VulnerabilitiesBySeverity.High,
				Open:     resultsSummary.VulnerabilitiesBySeverity.High,
			},
			{
				Severity: "medium",
				Total:    resultsSummary.VulnerabilitiesBySeverity.Medium,
				Open:     resultsSummary.VulnerabilitiesBySeverity.Medium,
			},
			{
				Severity: "low",
				Total:    resultsSummary.VulnerabilitiesBySeverity.Low,
				Open:     resultsSummary.VulnerabilitiesBySeverity.Low,
			},
		},
	}
	data, err = json.Marshal(summary)
	if err != nil {
		return nil, "", err
	}
	return data, content_type.TEST_SUMMARY, nil
}
