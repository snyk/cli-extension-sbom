package view

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-sbom/internal/severities"
)

func TestGenerateTestResult(t *testing.T) {
	untested, err := generateUntestedComponents([]Component{{
		Reference: "my reference 1",
		Info:      "my reason 1",
	}, {
		Reference: "my reference 2",
		Info:      "my reason 2",
	}, {
		Reference: "my reference 3",
		Info:      "my reason 3",
	}, {
		Reference: "my reference 4",
		Info:      "my reason 4",
	}}...)

	require.NoError(t, err)

	issues, err := generateIssues(
		OpenIssue{
			Severity:     severities.HighSeverity,
			Description:  "Improper Input Validation",
			IntroducedBy: []string{"https://python.org|python@2.7.18"},
			SnykRef:      "SNYK-UNMANAGED-PYTHON-3325575",
		},
		OpenIssue{
			Severity:     severities.LowSeverity,
			Description:  "Integer Overflow or Wraparound",
			IntroducedBy: []string{"curl@7.88.1-1.amzn2.0.1"},
			SnykRef:      "SNYK-AMZN2-CURL-6371161",
		},
		OpenIssue{
			Severity:    severities.CriticalSeverity,
			Description: "Integer Overflow or Wraparound",
			IntroducedBy: []string{
				"https://python.org|python@2.7.18",
				"https://python.org|python@2.7.20",
			},
			SnykRef: "SNYK-UNMANAGED-PYTHON-2317677",
		},
		OpenIssue{
			Severity:    severities.MediumSeverity,
			Description: "Integer Overflow or Wraparound",
			IntroducedBy: []string{
				"vim-minimal@9.0.1367-1.amzn2.0.1",
				"vim-minimal@9.0.2527-1.amzn2.0.1",
			},
			SnykRef: "SNYK-AMZN2-VIMMINIMAL-6062273",
		},
	)

	require.NoError(t, err)

	summary, err := generateSummary(
		"871BE73B-8763-4EEF-9C31-45B388FB05DA",
		"./sbom.dx",
		Summary{
			Low:          1,
			Medium:       1,
			High:         1,
			Critical:     1,
			TotalIssues:  4,
			UntestedPkgs: 4,
		},
	)

	require.NoError(t, err)

	sum, err := GenerateTestResult(
		"./sbom.dx",
		untested, issues, summary,
	)

	assert.NoError(t, err)

	snapshotter.SnapshotT(t, sum.String())
}

func TestGenerateTestResult_allComponentsTested(t *testing.T) {
	untested, err := generateUntestedComponents()

	require.NoError(t, err)

	issues, err := generateIssues(
		OpenIssue{
			Severity:     severities.HighSeverity,
			Description:  "Improper Input Validation",
			IntroducedBy: []string{"https://python.org|python@2.7.18"},
			SnykRef:      "SNYK-UNMANAGED-PYTHON-3325575",
		},
		OpenIssue{
			Severity:     severities.LowSeverity,
			Description:  "Integer Overflow or Wraparound",
			IntroducedBy: []string{"curl@7.88.1-1.amzn2.0.1"},
			SnykRef:      "SNYK-AMZN2-CURL-6371161",
		},
		OpenIssue{
			Severity:    severities.CriticalSeverity,
			Description: "Integer Overflow or Wraparound",
			IntroducedBy: []string{
				"https://python.org|python@2.7.18",
				"https://python.org|python@2.7.20",
			},
			SnykRef: "SNYK-UNMANAGED-PYTHON-2317677",
		},
		OpenIssue{
			Severity:    severities.MediumSeverity,
			Description: "Integer Overflow or Wraparound",
			IntroducedBy: []string{
				"vim-minimal@9.0.1367-1.amzn2.0.1",
				"vim-minimal@9.0.2527-1.amzn2.0.1",
			},
			SnykRef: "SNYK-AMZN2-VIMMINIMAL-6062273",
		},
	)

	require.NoError(t, err)

	summary, err := generateSummary(
		"871BE73B-8763-4EEF-9C31-45B388FB05DA",
		"./sbom.dx",
		Summary{
			Low:      1,
			Medium:   1,
			High:     1,
			Critical: 1,

			TotalIssues:  4,
			UntestedPkgs: 0,
		},
	)

	require.NoError(t, err)

	sum, err := GenerateTestResult(
		"./sbom.dx",
		untested, issues, summary,
	)

	assert.NoError(t, err)

	snapshotter.SnapshotT(t, sum.String())
}
