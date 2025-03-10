package sbommonitor

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_generateMonitorProject(t *testing.T) {
	project, err := generateMonitorProjectComponent(
		"My project",
		"https://example.com/my-project",
	)

	assert.NoError(t, err)

	snapshotter.SnapshotT(t, project.String())
}
