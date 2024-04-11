package sbomtest_test

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/bradleyjkemp/cupaloy/v2"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-sbom/internal/commands/sbomtest"
	"github.com/snyk/cli-extension-sbom/internal/snykclient"
)

//go:embed testdata/sbom-test-result.response.json
var response []byte

var snapshotter = cupaloy.New(cupaloy.SnapshotSubdirectory("testdata/snapshots"))

var res snykclient.SBOMTestResultResourceDocument

func init() {
	if err := json.Unmarshal(response, &res); err != nil {
		panic(err)
	}
	lipgloss.SetColorProfile(termenv.TrueColor)
}

func Test_RenderPrettyResult(t *testing.T) {
	var buf bytes.Buffer

	err := sbomtest.RenderPrettyResult(&buf, "e3ea3eb7-0e03-4373-ab7c-042e78182b79", "./path/to/sbom.cdx.json", res.AsResult())

	require.NoError(t, err)
	snapshotter.SnapshotT(t, buf.Bytes())
}

func Test_RenderJSONResult(t *testing.T) {
	var buf bytes.Buffer

	err := sbomtest.RenderJSONResult(&buf, res.AsResult())

	require.NoError(t, err)
	snapshotter.SnapshotT(t, buf.Bytes())
}
