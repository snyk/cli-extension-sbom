package sbommonitor

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_generateMonitor_oneProject(t *testing.T) {
	proj1, err := generateMonitorProjectComponent("Bob", "https://example.com/bob")
	require.NoError(t, err)
	projects := []monitorProjectComponent{proj1}

	monitor, err := generateMonitorComponent(projects)

	assert.NoError(t, err)

	snapshotter.SnapshotT(t, monitor.String())
}

func Test_generateMonitor_multipleProjects(t *testing.T) {
	proj1, err := generateMonitorProjectComponent("Bob", "https://example.com/bob")
	require.NoError(t, err)

	proj2, err := generateMonitorProjectComponent("Alice", "https://example.com/alice")
	require.NoError(t, err)

	projects := []monitorProjectComponent{proj1, proj2}

	monitor, err := generateMonitorComponent(projects)

	assert.NoError(t, err)

	snapshotter.SnapshotT(t, monitor.String())
}
