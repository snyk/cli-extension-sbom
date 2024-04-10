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

	fd, err := os.Open("testdata/humanReadable.input")
	require.NoError(t, err)

	var body snykclient.SBOMTestResultResourceDocument
	err = json.NewDecoder(fd).Decode(&body)
	require.NoError(t, err)

	data, contentType, err := sbomtest.Render("sbom.json", &body, sbomtest.FormatPretty, false, "CE818710-454E-49A5-8B6D-B7A8CBBED406")

	require.NoError(t, err)
	assert.Equal(t, "text/plain", contentType)

	snapshotter.SnapshotT(t, data)
}

func TestPresenter_JSON(t *testing.T) {
	mockICTX := createMockICTX(t)
	mockICTX.GetConfiguration().Set("json", true)

	fd, err := os.Open("testdata/humanReadable.input")
	require.NoError(t, err)

	var body snykclient.SBOMTestResultResourceDocument
	err = json.NewDecoder(fd).Decode(&body)
	require.NoError(t, err)

	data, contentType, err := sbomtest.Render("sbom.json", &body, sbomtest.FormatJSON, false, "CE818710-454E-49A5-8B6D-B7A8CBBED406")

	require.NoError(t, err)
	assert.Equal(t, "application/json", contentType)

	snapshotter.SnapshotT(t, data)
}
