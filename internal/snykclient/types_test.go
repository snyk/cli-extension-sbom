package snykclient_test

import (
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-sbom/internal/snykclient"
)

//go:embed testdata/sbom-test-result.response.json
var resultMock []byte

func TestSBOMTestResultResouceDocument_AsResult(t *testing.T) {
	var doc snykclient.SBOMTestResultResourceDocument
	err := json.Unmarshal(resultMock, &doc)
	require.NoError(t, err)

	result := doc.AsResult()

	assert.Equal(t, 140, result.Summary.TotalIssues)
	assert.Len(t, result.Summary.DocumentWarnings, 3)

	assert.Len(t, result.Packages, 103)
	assert.Len(t, result.Vulnerabilities, 138)
	assert.Len(t, result.LicenseIssues, 2)
}
