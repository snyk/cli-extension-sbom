package sbomtest //nolint:testpackage // we need testWorkflowImpl

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	codeclient "github.com/snyk/code-client-go"
	"github.com/snyk/code-client-go/bundle"
	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/code-client-go/scan"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-sbom/internal/bundlestore"
	svcmocks "github.com/snyk/cli-extension-sbom/internal/mocks"
)

func TestSBOMTestWorkflow_Reachability(t *testing.T) {
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

	mb := new(mockBundle)
	mb.On("GetBundleHash").Return(mockBundleHash)

	mcs := new(mockCodeScanner)
	mcs.On("Upload",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
	).Return(mb, nil)

	var scanner codeclient.CodeScanner = mcs
	scannerPtr := &scanner
	_, err = testWorkflowImpl(mockICTX, scannerPtr)
	require.NoError(t, err)

	require.Len(t, capturedRequests, 2)
	assert.Equal(t, http.MethodPost, capturedRequests[0].Method)
	assert.Equal(t, "/bundle", capturedRequests[0].URL.Path)
	assert.Equal(t, http.MethodPut, capturedRequests[1].Method)
	assert.Equal(t, "/bundle/"+mockBundleHash, capturedRequests[1].URL.Path)

	mcs.AssertCalled(
		t,
		"Upload",
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
	)
}

// Mocks

type mockCodeScanner struct {
	mock.Mock
}

func (m *mockCodeScanner) Upload(
	ctx context.Context,
	requestId string,
	target scan.Target,
	files <-chan string,
	changedFiles map[string]bool,
) (bundle.Bundle, error) {
	filesList := make([]string, 0)
	for file := range files {
		filesList = append(filesList, file)
	}

	args := m.Called(ctx, requestId, target, filesList, changedFiles)
	return args.Get(0).(bundle.Bundle), args.Error(1) //nolint:errcheck,forcetypeassert // test
}

func (m *mockCodeScanner) UploadAndAnalyze(
	ctx context.Context,
	requestId string,
	target scan.Target,
	files <-chan string,
	changedFiles map[string]bool,
) (*sarif.SarifResponse, string, error) {
	filesList := make([]string, 0)
	for file := range files {
		filesList = append(filesList, file)
	}

	args := m.Called(ctx, requestId, target, filesList, changedFiles)
	return args.Get(0).(*sarif.SarifResponse), args.String(1), args.Error(2) //nolint:errcheck,forcetypeassert // test
}

var _ codeclient.CodeScanner = (*mockCodeScanner)(nil)

type mockBundle struct {
	mock.Mock
}

func (m *mockBundle) UploadBatch(ctx context.Context, requestId string, batch *bundle.Batch) error {
	args := m.Called(ctx, requestId, batch)
	return args.Error(0)
}

func (m *mockBundle) GetBundleHash() string {
	args := m.Called()
	return args.String(0)
}

func (m *mockBundle) GetFiles() map[string]bundle.BundleFile {
	args := m.Called()
	return args.Get(0).(map[string]bundle.BundleFile) //nolint:errcheck,forcetypeassert // test
}

func (m *mockBundle) GetMissingFiles() []string {
	args := m.Called()
	return args.Get(0).([]string) //nolint:errcheck,forcetypeassert // test
}

func (m *mockBundle) GetLimitToFiles() []string {
	args := m.Called()
	return args.Get(0).([]string) //nolint:errcheck,forcetypeassert // test
}

func (m *mockBundle) GetRootPath() string {
	args := m.Called()
	return args.String(0)
}

var _ bundle.Bundle = (*mockBundle)(nil)

// Helpers

func createMockICTXWithURL(t *testing.T, sbomServiceURL string) workflow.InvocationContext {
	t.Helper()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	return mockInvocationContext(t, ctrl, sbomServiceURL, nil)
}

func mockInvocationContext(
	t *testing.T,
	ctrl *gomock.Controller,
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
