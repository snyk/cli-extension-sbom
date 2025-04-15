package sbomtest_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-sbom/internal/bundlestore"
	"github.com/snyk/cli-extension-sbom/internal/commands/sbomtest"
	svcmocks "github.com/snyk/cli-extension-sbom/internal/mocks"
)

func TestSBOMTestWorkflow_Reachability(t *testing.T) {
	mockBundleHash := "mockHash123abc"

	createBundleResponse := bundlestore.BundleResponse{
		BundleHash:   mockBundleHash,
		MissingFiles: []string{},
	}
	createBundleJSON, err := json.Marshal(createBundleResponse)
	require.NoError(t, err)

	extendBundleResponse := bundlestore.BundleResponse{
		BundleHash:   mockBundleHash,
		MissingFiles: []string{},
	}
	extendBundleJSON, err := json.Marshal(extendBundleResponse)
	require.NoError(t, err)

	responses := []svcmocks.MockResponse{
		svcmocks.NewMockResponse("application/json", createBundleJSON, http.StatusOK),
		svcmocks.NewMockResponse("application/json", extendBundleJSON, http.StatusOK),
	}

	var capturedRequests []*http.Request
	mockService := svcmocks.NewMockSBOMServiceMultiResponse(responses, func(r *http.Request) {
		capturedRequests = append(capturedRequests, r)
	})
	defer mockService.Close()

	mockICTX := createMockICTXWithURL(t, mockService.URL)
	mockICTX.GetConfiguration().Set("experimental", true)
	mockICTX.GetConfiguration().Set("file", "testdata/bom.json")
	mockICTX.GetConfiguration().Set("json", true)

	t.Setenv("SNYK_DEV_REACHABILITY", "true")

	_, err = sbomtest.TestWorkflow(mockICTX, []workflow.Data{})
	require.NoError(t, err)

	require.Len(t, capturedRequests, 2)

	assert.Equal(t, http.MethodPost, capturedRequests[0].Method)
	assert.Equal(t, "/bundle", capturedRequests[0].URL.Path)

	assert.Equal(t, http.MethodPut, capturedRequests[1].Method)
	assert.Equal(t, "/bundle/"+mockBundleHash, capturedRequests[1].URL.Path)
}
