package view

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-sbom/internal/severities"
)

func TestRender(t *testing.T) {
	var buff bytes.Buffer

	untested := []Component{{
		Reference: "fa08b68d9188550d",
		Info:      "component must have a PackageUR",
	}, {
		Reference: "amzn",
		Info:      "component must have a PackageURL",
	}}

	issues := []OpenIssue{{
		Severity:     severities.HighSeverity,
		Description:  "Improper Input Validation",
		IntroducedBy: []string{"https://python.org|python@2.7.18"},
		SnykRef:      "SNYK-UNMANAGED-PYTHON-3325575",
	}, {
		Severity:     severities.LowSeverity,
		Description:  "Integer Overflow or Wraparound",
		IntroducedBy: []string{"curl@7.88.1-1.amzn2.0.1"},
		SnykRef:      "SNYK-AMZN2-CURL-6371161",
	}, {
		Severity:    severities.CriticalSeverity,
		Description: "Integer Overflow or Wraparound",
		IntroducedBy: []string{
			"https://python.org|python@2.7.18",
			"https://python.org|python@2.7.20",
		},
		SnykRef: "SNYK-UNMANAGED-PYTHON-2317677",
	}, {
		Severity:    severities.MediumSeverity,
		Description: "Integer Overflow or Wraparound",
		IntroducedBy: []string{
			"vim-minimal@9.0.1367-1.amzn2.0.1",
			"vim-minimal@9.0.2527-1.amzn2.0.1",
		},
		SnykRef: "SNYK-AMZN2-VIMMINIMAL-6062273",
	}}

	org := "871BE73B-8763-4EEF-9C31-45B388FB05DA"
	path := "./sbom.dx"

	summary := Summary{
		Low:         1,
		Medium:      1,
		High:        1,
		Critical:    1,
		TotalIssues: 4,
	}

	p := Presentation{
		Org:      org,
		Path:     path,
		Untested: untested,
		Issues:   issues,
		Summary:  summary,
	}

	_, err := Render(&buff, &p)
	assert.NoError(t, err)

	snapshotter.SnapshotT(t, buff.String())
}

func TestRender_nothingToTest(t *testing.T) {
	var buff bytes.Buffer

	org := "871BE73B-8763-4EEF-9C31-45B388FB05DA"
	path := "./sbom.dx"

	p := Presentation{
		Org:      org,
		Path:     path,
		Untested: nil,
		Issues:   nil,
		Summary:  Summary{},
	}

	_, err := Render(&buff, &p)
	assert.NoError(t, err)

	snapshotter.SnapshotT(t, buff.String())
}

func TestRender_onlyUntestedPackages(t *testing.T) {
	var buff bytes.Buffer

	org := "871BE73B-8763-4EEF-9C31-45B388FB05DA"
	path := "./sbom.dx"

	untested := []Component{{
		Reference: "fa08b68d9188550d",
		Info:      "component must have a PackageUR",
	}, {
		Reference: "amzn",
		Info:      "component must have a PackageURL",
	}}

	p := Presentation{
		Org:      org,
		Path:     path,
		Untested: untested,
		Issues:   nil,
		Summary:  Summary{},
	}

	_, err := Render(&buff, &p)
	assert.NoError(t, err)

	snapshotter.SnapshotT(t, buff.String())
}
