package severities_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-sbom/internal/severities"
)

func TestParse(t *testing.T) {
	cases := map[string]severities.Level{
		"low": severities.LowSeverity,
		"lOW": severities.LowSeverity,
		"LOW": severities.LowSeverity,

		"medium": severities.MediumSeverity,
		"medIUM": severities.MediumSeverity,
		"MEDIUM": severities.MediumSeverity,

		"high": severities.HighSeverity,
		"hiGH": severities.HighSeverity,
		"HIGH": severities.HighSeverity,

		"critical": severities.CriticalSeverity,
		"critiCAL": severities.CriticalSeverity,
		"CRITICAL": severities.CriticalSeverity,
	}

	for name, expected := range cases {
		actual, err := severities.Parse(name)

		assert.NoError(t, err)
		assert.Equal(t, expected, actual)
	}
}

func TestParse_InvalidInput(t *testing.T) {
	cases := []string{"", "random"}

	for _, input := range cases {
		_, err := severities.Parse(input)
		assert.Error(t, err)
	}
}

func TestLevel_UnmarshalJSON(t *testing.T) {
	tc := []struct {
		marshaled string
		expected  severities.Level
	}{
		{`"low"`, severities.LowSeverity},
		{`"medium"`, severities.MediumSeverity},
		{`"high"`, severities.HighSeverity},
		{`"critical"`, severities.CriticalSeverity},
	}

	for _, tt := range tc {
		t.Run(tt.marshaled, func(t *testing.T) {
			var l severities.Level
			err := json.Unmarshal([]byte(tt.marshaled), &l)
			require.NoError(t, err)

			assert.Equal(t, tt.expected, l)
		})
	}
}
