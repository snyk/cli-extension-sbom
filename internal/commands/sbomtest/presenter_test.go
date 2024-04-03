package sbomtest_test

import (
	"testing"

	"github.com/bradleyjkemp/cupaloy/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-sbom/internal/commands/sbomtest"
)

var snapshotter = cupaloy.New(cupaloy.SnapshotSubdirectory("testdata/snapshots"))

var mockResult = sbomtest.TestResult{ // TODO: assign the actual test result
	Summary: sbomtest.TestSummary{TotalVulnerabilities: 42},
}

func TestPresenter_Pretty(t *testing.T) {
	presenter := &sbomtest.Presenter{
		Format: sbomtest.PresenterFormatPretty,
	}

	data, contentType, err := presenter.Render(mockResult)

	require.NoError(t, err)
	assert.Equal(t, "text/plain", contentType)
	snapshotter.SnapshotT(t, data)
}

func TestPresenter_JSON(t *testing.T) {
	presenter := &sbomtest.Presenter{
		Format: sbomtest.PresenterFormatJSON,
	}

	data, contentType, err := presenter.Render(mockResult)

	require.NoError(t, err)
	assert.Equal(t, "application/json", contentType)
	snapshotter.SnapshotT(t, data)
}
