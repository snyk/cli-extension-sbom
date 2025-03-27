package sbommonitor

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-sbom/internal/snykclient"
)

func TestRenderer_RenderMonitor(t *testing.T) {
	var buf bytes.Buffer
	r := NewRenderer(&buf)

	require.NoError(t, r.RenderMonitor(
		&snykclient.MonitorDependenciesResponse{
			ProjectName: "Test Project",
			URI:         "https://example.com/test_project"}, nil))

	out := buf.String()

	assert.Contains(t, out, "Test Project")
	assert.Contains(t, out, "https://example.com/test_project")

	snapshotter.SnapshotT(t, out)
}

func TestRenderer_RenderMonitor_MultipleProjects(t *testing.T) {
	var buf bytes.Buffer
	r := NewRenderer(&buf)

	require.NoError(t, r.RenderMonitor(
		&snykclient.MonitorDependenciesResponse{
			ProjectName: "Test Project",
			URI:         "https://example.com/test_project"}, nil))
	require.NoError(t, r.RenderMonitor(
		&snykclient.MonitorDependenciesResponse{
			ProjectName: "A Different Project",
			URI:         "https://example.com/different_project"}, nil))

	out := buf.String()

	assert.Contains(t, out, "Test Project")
	assert.Contains(t, out, "https://example.com/test_project")
	assert.Contains(t, out, "A Different Project")
	assert.Contains(t, out, "https://example.com/different_project")

	snapshotter.SnapshotT(t, out)
}

func TestRenderer_RenderMonitor_WithError(t *testing.T) {
	var buf bytes.Buffer
	r := NewRenderer(&buf)

	require.NoError(t, r.RenderMonitor(
		&snykclient.MonitorDependenciesResponse{
			ProjectName: "Test Project",
			URI:         "https://example.com/test_project"}, nil))
	require.NoError(t, r.RenderMonitor(
		nil, errors.New("something is very wrong!")))

	out := buf.String()

	snapshotter.SnapshotT(t, out)
}
