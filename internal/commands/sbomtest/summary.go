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
				Total:    resultsSummary.IssuesBySeverity.Critical,
				Open:     resultsSummary.IssuesBySeverity.Critical,
			},
			{
				Severity: "high",
				Total:    resultsSummary.IssuesBySeverity.High,
				Open:     resultsSummary.IssuesBySeverity.High,
			},
			{
				Severity: "medium",
				Total:    resultsSummary.IssuesBySeverity.Medium,
				Open:     resultsSummary.IssuesBySeverity.Medium,
			},
			{
				Severity: "low",
				Total:    resultsSummary.IssuesBySeverity.Low,
				Open:     resultsSummary.IssuesBySeverity.Low,
			},
		},
	}
	data, err = json.Marshal(summary)
	if err != nil {
		return nil, "", err
	}
	return data, content_type.TEST_SUMMARY, nil
}
