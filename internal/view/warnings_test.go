package view

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_generatewarnings(t *testing.T) {
	warnings, err := generateWarnings(
		"Dependency graph is invalid. It references unknown component \"463-write-file-atomic@2.4.3\".",
		"The given SBOM contains an invalid dependency graph.",
		"Falling back on analysis without dependency graph information.")

	require.NoError(t, err)
	require.NotNil(t, warnings)

	snapshotter.SnapshotT(t, warnings.String())
}

func Test_generateWarnings_no_warnings(t *testing.T) {
	result, err := generateWarnings()

	require.NoError(t, err)
	assert.Equal(t, "", result.String())
}
