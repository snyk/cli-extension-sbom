package sbomtest_test

import (
	"testing"

	"github.com/bradleyjkemp/cupaloy/v2"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-sbom/internal/commands/sbomtest"
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
