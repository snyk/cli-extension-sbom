package snykclient_test

import (
	"encoding/json"
	"testing"

	"github.com/snyk/cli-extension-sbom/internal/snykclient"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_SortIncludes(t *testing.T) {
	includes := []*snykclient.Includes{{
		Type: snykclient.Vulnerabilities,
	}, {
		Type: snykclient.Remedies,
	}, {
		Type: snykclient.Packages,
	}, {
		Type: snykclient.Vulnerabilities,
	}, {
		Type: snykclient.Remedies,
	}, {
		Type: snykclient.Packages,
	}}

	includes[0].Attributes.EffectiveSeverityLevel = snykclient.CriticalSeverity
	includes[3].Attributes.EffectiveSeverityLevel = snykclient.LowSeverity

	view := snykclient.SortIncludes(includes)

	require.Equal(t, includes[0].Type, snykclient.Packages)
	require.Equal(t, includes[1].Type, snykclient.Packages)

	require.Equal(t, includes[2].Type, snykclient.Remedies)
	require.Equal(t, includes[3].Type, snykclient.Remedies)

	require.Equal(t, includes[4].Type, snykclient.Vulnerabilities)
	require.Equal(t, includes[5].Type, snykclient.Vulnerabilities)

	require.Len(t, view.Packages, 2)
	require.Equal(t, view.Packages[0].Type, snykclient.Packages)
	require.Equal(t, view.Packages[1].Type, snykclient.Packages)

	require.Len(t, view.Remedies, 2)
	require.Equal(t, view.Remedies[0].Type, snykclient.Remedies)
	require.Equal(t, view.Remedies[1].Type, snykclient.Remedies)

	require.Len(t, view.Vulnerabilities, 2)
	require.Equal(t, view.Vulnerabilities[0].Type, snykclient.Vulnerabilities)
	require.Equal(t, view.Vulnerabilities[1].Type, snykclient.Vulnerabilities)

	require.Equal(t, view.Vulnerabilities[0].Attributes.EffectiveSeverityLevel, snykclient.LowSeverity)
	require.Equal(t, view.Vulnerabilities[1].Attributes.EffectiveSeverityLevel, snykclient.CriticalSeverity)
}

func TestSeverityLevel_UnmarshalJSON(t *testing.T) {
	tc := []struct {
		marshaled string
		expected  snykclient.SeverityLevel
	}{
		{`"low"`, snykclient.LowSeverity},
		{`"medium"`, snykclient.MediumSeverity},
		{`"high"`, snykclient.HighSeverity},
		{`"critical"`, snykclient.CriticalSeverity},
	}

	for _, tt := range tc {
		t.Run(tt.marshaled, func(t *testing.T) {
			var l snykclient.SeverityLevel
			err := json.Unmarshal([]byte(tt.marshaled), &l)
			require.NoError(t, err)

			assert.Equal(t, tt.expected, l)
		})
	}
}
