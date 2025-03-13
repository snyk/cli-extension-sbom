package sbommonitor

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-sbom/internal/snykclient"
)

func TestRenderMonitor(t *testing.T) {
	monitors := []*snykclient.MonitorDependenciesResponse{
		{ProjectName: "Test Project", URI: "https://example.com/test_project"},
	}

	var buf bytes.Buffer
	_, err := RenderMonitor(&buf, monitors)
	require.NoError(t, err)

	output := buf.String()

	assert.Contains(t, output, monitors[0].ProjectName, "Output should contain the project name")
	assert.Contains(t, output, monitors[0].URI, "Output should contain the URI")

	snapshotter.SnapshotT(t, output)
}

func TestRenderMonitor_MultipleProjects(t *testing.T) {
	monitors := []*snykclient.MonitorDependenciesResponse{
		{ProjectName: "Test Project", URI: "https://example.com/test_project"},
		{ProjectName: "A Different Project", URI: "https://example.com/different_project"},
	}

	var buf bytes.Buffer
	_, err := RenderMonitor(&buf, monitors)
	require.NoError(t, err)

	output := buf.String()

	for _, m := range monitors {
		assert.Contains(t, output, m.ProjectName, "Output should contain the project name")
		assert.Contains(t, output, m.URI, "Output should contain the URI")
	}

	snapshotter.SnapshotT(t, output)
}
