package sbomtest_test

import (
	"testing"

	"github.com/bradleyjkemp/cupaloy/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-sbom/internal/commands/sbomtest"
	"github.com/snyk/cli-extension-sbom/internal/snykclient"
)

var snapshotter = cupaloy.New(cupaloy.SnapshotSubdirectory("testdata/snapshots"))

var mockResult = &snykclient.GetSBOMTestResultResponseBody{
	Data: &snykclient.GetSBOMTestResultResponseData{
		Attributes: snykclient.SBOMTestRunAttributes{
			Summary: snykclient.SBOMTestRunSummary{TotalVulnerabilities: 42},
		},
	},
}

func TestPresenter_Pretty(t *testing.T) {
	mockICTX := createMockICTX(t)
	mockICTX.GetConfiguration().Set("experimental", true)
	mockICTX.GetConfiguration().Set("print-deps", true)
	mockICTX.GetConfiguration().Set("file", "testdata/humanReadable.input")
	mockICTX.GetConfiguration().Set("json", false)
	presenter := sbomtest.NewPresenter(mockICTX)

	data, contentType, err := presenter.Render("sbom.json", mockResult, true)

	require.NoError(t, err)
	assert.Equal(t, "text/plain", contentType)
	snapshotter.SnapshotT(t, data)
}

func TestPresenter_JSON(t *testing.T) {
	mockICTX := createMockICTX(t)
	mockICTX.GetConfiguration().Set("json", true)
	mockICTX.GetConfiguration().Set("file", "testdata/humanReadable.input")
	presenter := sbomtest.NewPresenter(mockICTX)

	data, contentType, err := presenter.Render("sbom.json", mockResult, false)

	require.NoError(t, err)
	assert.Equal(t, "application/json", contentType)
	snapshotter.SnapshotT(t, data)
}
