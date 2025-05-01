package sbomtest_test

import (
	"encoding/json"
	"net/http"
	"testing"

	gomock_deprecated "github.com/golang/mock/gomock"
	"go.uber.org/mock/gomock"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	bundlemocks "github.com/snyk/code-client-go/bundle/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-sbom/internal/bundlestore"
	"github.com/snyk/cli-extension-sbom/internal/commands/sbomtest"
	svcmocks "github.com/snyk/cli-extension-sbom/internal/mocks"
)

//go:generate go run go.uber.org/mock/mockgen -package=mocks -destination=../../mocks/mock_codescanner.go github.com/snyk/code-client-go CodeScanner

func TestSBOMTestWorkflow_Reachability(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	ctrl_dep := gomock_deprecated.NewController(t)
	defer ctrl_dep.Finish()

	mockBundleHash := "mockHash123abc"

	bundleRespJSON, err := json.Marshal(bundlestore.BundleResponse{
		BundleHash:   mockBundleHash,
		MissingFiles: []string{},
	})
	require.NoError(t, err)

	responses := []svcmocks.MockResponse{
		svcmocks.NewMockResponse("application/json", bundleRespJSON, http.StatusOK),
		svcmocks.NewMockResponse("application/json", bundleRespJSON, http.StatusOK),
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

	mockBundle := bundlemocks.NewMockBundle(ctrl_dep)
	mockBundle.EXPECT().
		GetBundleHash().
		Return(mockBundleHash).
		Times(1)
	mockCodeScanner := svcmocks.NewMockCodeScanner(ctrl)
	mockCodeScanner.EXPECT().
		Upload(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(mockBundle, nil).
		Times(1)
	bundlestore.CodeScanner = mockCodeScanner

	_, err = sbomtest.TestWorkflow(mockICTX, []workflow.Data{})
	require.NoError(t, err)

	require.Len(t, capturedRequests, 2)

	assert.Equal(t, http.MethodPost, capturedRequests[0].Method)
	assert.Equal(t, "/bundle", capturedRequests[0].URL.Path)

	assert.Equal(t, http.MethodPut, capturedRequests[1].Method)
	assert.Equal(t, "/bundle/"+mockBundleHash, capturedRequests[1].URL.Path)
}
