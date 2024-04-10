package view

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_generateUntestedComponents(t *testing.T) {
	untestedComponets := []Component{{
		Reference: "my reference 1",
		Info:      "my reason 1",
	}, {
		Reference: "my reference 2",
		Info:      "my reason 2",
	}, {
		Reference: "my reference 3",
		Info:      "my reason 3",
	}, {
		Reference: "my reference 4",
		Info:      "my reason 4",
	}}

	untested, err := generateUntestedComponents(untestedComponets...)

	assert.NoError(t, err)

	snapshotter.SnapshotT(t, untested.String())
}

func Test_generateUntestedComponents_no_components(t *testing.T) {
	untestedComponets := []Component{}

	result, err := generateUntestedComponents(untestedComponets...)

	assert.NoError(t, err)
	assert.Equal(t, "", result.String())
}

func Test_generateUntestedComponents_nil_as_argument(t *testing.T) {
	var untestedComponets []Component

	result, err := generateUntestedComponents(untestedComponets...)

	assert.NoError(t, err)
	assert.Equal(t, "", result.String())
}
