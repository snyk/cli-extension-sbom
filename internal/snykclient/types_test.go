package snykclient_test

import (
	"encoding/json"
	"testing"

	"github.com/snyk/cli-extension-sbom/internal/snykclient"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
