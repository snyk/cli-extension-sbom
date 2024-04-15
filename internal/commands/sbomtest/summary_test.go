package sbomtest_test

import (
	"testing"

	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-sbom/internal/commands/sbomtest"
	"github.com/snyk/cli-extension-sbom/internal/snykclient"
)

func TestBuilTestSummary(t *testing.T) {
	mockResultsSummary := &snykclient.SBOMTestSummary{
		VulnerabilitiesBySeverity: struct {
			Critical int `json:"critical"`
			High     int `json:"high"`
			Medium   int `json:"medium"`
			Low      int `json:"low"`
		}{
			Critical: 8,
			High:     19,
			Medium:   12,
			Low:      3,
		},
	}

	data, contentType, err := sbomtest.BuildTestSummary(mockResultsSummary)

	require.NoError(t, err)
	require.Equal(t, content_type.TEST_SUMMARY, contentType)
	snapshotter.SnapshotT(t, data)
}
