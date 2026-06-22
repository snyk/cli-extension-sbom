package sbommonitor

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-sbom/internal/snykclient"
)

func TestRenderer_RenderWarnings_NoWarnings(t *testing.T) {
	var buf bytes.Buffer
	r := NewRenderer(&buf)

	require.NoError(t, r.RenderWarnings([]*snykclient.ConversionWarning{}))

	out := buf.String()
	snapshotter.SnapshotT(t, out)
}

func TestRenderer_RenderWarnings(t *testing.T) {
	var buf bytes.Buffer
	r := NewRenderer(&buf)

	require.NoError(t, r.RenderWarnings([]*snykclient.ConversionWarning{
		{Type: "NoComponents", Msg: "This is a warning"},
	}))

	out := buf.String()

	assert.Contains(t, out, "[NoComponents]")
	assert.Contains(t, out, "This is a warning")
	snapshotter.SnapshotT(t, out)
}

func TestRenderer_RenderWarningWithBOMRef(t *testing.T) {
	var buf bytes.Buffer
	r := NewRenderer(&buf)

	require.NoError(t, r.RenderWarnings([]*snykclient.ConversionWarning{
		{Type: "NoComponents", Msg: "This is a warning", BOMRef: "some-ref"},
	}))

	out := buf.String()

	assert.Contains(t, out, "[NoComponents]")
	assert.Contains(t, out, "This is a warning")
	assert.Contains(t, out, "some-ref")
	snapshotter.SnapshotT(t, out)
}

func TestRenderer_RenderMultipleWarnings(t *testing.T) {
	var buf bytes.Buffer
	r := NewRenderer(&buf)

	require.NoError(t, r.RenderWarnings([]*snykclient.ConversionWarning{
		{Type: "NoComponents", Msg: "This is a warning"},
		{Type: "NoRootNode", Msg: "A warning about root nodes"},
	}))

	out := buf.String()

	assert.Contains(t, out, "[NoComponents]")
	assert.Contains(t, out, "This is a warning")
	assert.Contains(t, out, "[NoRootNode]")
	assert.Contains(t, out, "A warning about root nodes")

	snapshotter.SnapshotT(t, out)
}

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
