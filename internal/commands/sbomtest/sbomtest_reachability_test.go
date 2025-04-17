package sbomtest //nolint:testpackage // we need testWorkflowImpl

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	gomock_deprecated "github.com/golang/mock/gomock"
	"go.uber.org/mock/gomock"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	codeclient "github.com/snyk/code-client-go"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-sbom/internal/bundlestore"
	svcmocks "github.com/snyk/cli-extension-sbom/internal/mocks"
)

//go:generate go run go.uber.org/mock/mockgen -package=mocks -destination=../../mocks/mock_codescanner.go github.com/snyk/code-client-go CodeScanner
//go:generate go run go.uber.org/mock/mockgen -package=mocks -destination=../../mocks/mock_bundle.go github.com/snyk/code-client-go/bundle Bundle

func TestSBOMTestWorkflow_Reachability(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

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

	mockBundle := svcmocks.NewMockBundle(ctrl)
	mockCodeScanner := svcmocks.NewMockCodeScanner(ctrl)

	mockCodeScanner.EXPECT().
		Upload(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(mockBundle, nil).
		Times(1)

	mockBundle.EXPECT().
		GetBundleHash().
		Return(mockBundleHash).
		Times(1)

	var scanner codeclient.CodeScanner = mockCodeScanner
	scannerPtr := &scanner
	_, err = testWorkflowImpl(mockICTX, scannerPtr)
	require.NoError(t, err)

	require.Len(t, capturedRequests, 2)
	assert.Equal(t, http.MethodPost, capturedRequests[0].Method)
	assert.Equal(t, "/bundle", capturedRequests[0].URL.Path)
	assert.Equal(t, http.MethodPut, capturedRequests[1].Method)
	assert.Equal(t, "/bundle/"+mockBundleHash, capturedRequests[1].URL.Path)
}

// Helpers

func createMockICTXWithURL(t *testing.T, sbomServiceURL string) workflow.InvocationContext {
	t.Helper()

	ctrl := gomock_deprecated.NewController(t)
	defer ctrl.Finish()
	return mockInvocationContext(t, ctrl, sbomServiceURL, nil)
}

func mockInvocationContext(
	t *testing.T,
	ctrl *gomock_deprecated.Controller,
	sbomServiceURL string,
	mockEngine *mocks.MockEngine,
) workflow.InvocationContext {
	t.Helper()

	mockLogger := zerolog.New(io.Discard)

	mockConfig := configuration.New()
	mockConfig.Set(configuration.AUTHENTICATION_TOKEN, "<SOME API TOKEN>")
	mockConfig.Set(configuration.ORGANIZATION, "6277734c-fc84-4c74-9662-33d46ec66c53")
	mockConfig.Set(configuration.API_URL, sbomServiceURL)
	mockConfig.Set("format", "cyclonedx1.4+json")
	mockConfig.Set("name", "goof")
	mockConfig.Set("version", "0.0.0")

	mockRuntimeInfo := runtimeinfo.New(
		runtimeinfo.WithName("test-app"),
		runtimeinfo.WithVersion("1.2.3"))

	ictx := mocks.NewMockInvocationContext(ctrl)
	ictx.EXPECT().GetConfiguration().Return(mockConfig).AnyTimes()
	ictx.EXPECT().GetEngine().Return(mockEngine).AnyTimes()
	ictx.EXPECT().GetNetworkAccess().Return(networking.NewNetworkAccess(mockConfig)).AnyTimes()
	ictx.EXPECT().GetEnhancedLogger().Return(&mockLogger).AnyTimes()
	ictx.EXPECT().GetRuntimeInfo().Return(mockRuntimeInfo).AnyTimes()

	return ictx
}
