package view

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_generateSummary(t *testing.T) {
	sum, err := generateSummary(
		"871BE73B-8763-4EEF-9C31-45B388FB05DA",
		"./sbom.dx",
		Summary{
			Low:         10,
			Medium:      20,
			High:        30,
			Critical:    40,
			TotalIssues: 100,
		},
	)

	assert.NoError(t, err)

	snapshotter.SnapshotT(t, sum.String())
}
