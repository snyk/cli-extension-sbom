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
	assert.Nil(t, err)

	var body snykclient.GetSBOMTestResultResponseBody

	err = json.NewDecoder(fd).Decode(&body)
	assert.Nil(t, err)

	result := sbomtest.AsHumanReadable("./fake/dir", &body, true)

	snapshotter.SnapshotT(t, result)

	dst, err := os.Create("/tmp/result.json")
	require.Nil(t, err)
	defer dst.Close()

	dst.WriteString(result)
	//enc := json.NewEncoder(dst)
	//enc.Encode(result)
}
