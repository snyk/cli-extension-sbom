package sbomtest_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/bradleyjkemp/cupaloy/v2"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-sbom/internal/commands/sbomtest"
	"github.com/snyk/cli-extension-sbom/internal/snykclient"
)

var snapshotter = cupaloy.New(cupaloy.SnapshotSubdirectory("testdata/snapshots"))

func TestPresenter_Pretty(t *testing.T) {
	mockICTX := createMockICTX(t)
	mockICTX.GetConfiguration().Set("experimental", true)

	data, err := sbomtest.TestWorkflow(mockICTX, []workflow.Data{})

	require.NoError(t, err)
	require.Len(t, data, 1)

	assert.Equal(t, "text/plain", data[0].GetContentType())
	snapshotter.SnapshotT(t, data[0].GetPayload())
}

func TestPresenter_JSON(t *testing.T) {
	mockICTX := createMockICTX(t)
	mockICTX.GetConfiguration().Set("experimental", true)
	mockICTX.GetConfiguration().Set("json", true)

	data, err := sbomtest.TestWorkflow(mockICTX, []workflow.Data{})

	require.NoError(t, err)
	require.Len(t, data, 1)

	assert.Equal(t, "application/json", data[0].GetContentType())
	snapshotter.SnapshotT(t, data[0].GetPayload())
}

func TestPresenter_asHumanReadable(t *testing.T) {
	fd, err := os.Open("testdata/humanReadable.input")
	require.Nil(t, err)

	var body snykclient.GetSBOMTestResultResponseBody

	err = json.NewDecoder(fd).Decode(&body)
	require.Nil(t, err)

	resources := snykclient.ToResources(body.Data.Attributes.Summary.Tested, body.Included)
	result := sbomtest.AsHumanReadable("./fake/dir", resources, true)

	snapshotter.SnapshotT(t, result)
}

func TestSortVulns(t *testing.T) {
	vulns := map[string]snykclient.VulnerabilityResource{
		"0": {
			ID:            "0",
			SeverityLevel: snykclient.MediumSeverity,
		},
		"1": {
			ID:            "1",
			SeverityLevel: snykclient.CriticalSeverity,
		},
		"2": {
			ID:            "2",
			SeverityLevel: snykclient.LowSeverity,
		},
		"3": {
			ID:            "3",
			SeverityLevel: snykclient.HighSeverity,
		},
	}

	result := sbomtest.SortVulns(vulns)

	require.Equal(t, "2", result[0].ID)
	require.Equal(t, snykclient.LowSeverity, result[0].SeverityLevel)

	require.Equal(t, "0", result[1].ID)
	require.Equal(t, snykclient.MediumSeverity, result[1].SeverityLevel)

	require.Equal(t, "3", result[2].ID)
	require.Equal(t, snykclient.HighSeverity, result[2].SeverityLevel)

	require.Equal(t, "1", result[3].ID)
	require.Equal(t, snykclient.CriticalSeverity, result[3].SeverityLevel)
}
