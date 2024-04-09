package sbomtest_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/bradleyjkemp/cupaloy/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-sbom/internal/commands/sbomtest"
	"github.com/snyk/cli-extension-sbom/internal/snykclient"
)

var snapshotter = cupaloy.New(cupaloy.SnapshotSubdirectory("testdata/snapshots"))

func TestPresenter_Pretty(t *testing.T) {
	mockICTX := createMockICTX(t)
	mockICTX.GetConfiguration().Set("json", false)

	presenter := sbomtest.NewPresenter(mockICTX)

	fd, err := os.Open("testdata/humanReadable.input")
	require.NoError(t, err)

	var body snykclient.GetSBOMTestResultResponseBody
	err = json.NewDecoder(fd).Decode(&body)
	require.NoError(t, err)

	data, contentType, err := presenter.Render("sbom.json", &body, true)

	require.NoError(t, err)
	assert.Equal(t, "text/plain", contentType)

	snapshotter.SnapshotT(t, data)
}

func TestPresenter_JSON(t *testing.T) {
	mockICTX := createMockICTX(t)
	mockICTX.GetConfiguration().Set("json", true)

	presenter := sbomtest.NewPresenter(mockICTX)

	fd, err := os.Open("testdata/humanReadable.input")
	require.NoError(t, err)

	var body snykclient.GetSBOMTestResultResponseBody
	err = json.NewDecoder(fd).Decode(&body)
	require.NoError(t, err)

	data, contentType, err := presenter.Render("sbom.json", &body, false)

	require.NoError(t, err)
	assert.Equal(t, "application/json", contentType)

	snapshotter.SnapshotT(t, data)
}
