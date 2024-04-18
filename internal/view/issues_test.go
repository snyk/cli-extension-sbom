package view

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-sbom/internal/severities"
)

func Test_generateIssues(t *testing.T) {
	sum, err := generateIssues(
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

	assert.NoError(t, err)

	snapshotter.SnapshotT(t, sum.String())
}

func Test_generateIssues_noIssues(t *testing.T) {
	sum, err := generateIssues()
	assert.NoError(t, err)

	snapshotter.SnapshotT(t, sum.String())
}
