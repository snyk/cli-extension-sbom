package sbomtest_test

import (
	_ "embed"
	"io"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-sbom/internal/commands/sbomtest"
	svcmocks "github.com/snyk/cli-extension-sbom/internal/mocks"
)

//go:embed testdata/sbom-test-result.response.json
var testResultMockResponse []byte

func TestSBOMTestWorkflow_NoExperimentalFlag(t *testing.T) {
	mockICTX := createMockICTX(t)

	_, err := sbomtest.TestWorkflow(mockICTX, []workflow.Data{})

	assert.ErrorContains(t, err, "Flag `--experimental` is required to execute this command.")
}

func TestSBOMTestWorkflow_NoFileFlag(t *testing.T) {
	mockICTX := createMockICTX(t)
	mockICTX.GetConfiguration().Set("experimental", true)

	_, err := sbomtest.TestWorkflow(mockICTX, []workflow.Data{})

	assert.ErrorContains(t, err, "Flag `--file` is required to execute this command. Value should point to a valid SBOM document.")
}

func TestSBOMTestWorkflow_SupplyMissingFile(t *testing.T) {
	mockICTX := createMockICTX(t)
	mockICTX.GetConfiguration().Set("experimental", true)
	mockICTX.GetConfiguration().Set("file", "missing-file.txt")

	_, err := sbomtest.TestWorkflow(mockICTX, []workflow.Data{})

	assert.ErrorContains(t, err, "The given filepath \"missing-file.txt\" does not exist.")
}

func TestSBOMTestWorkflow_SuccessPretty(t *testing.T) {
	responses := []svcmocks.MockResponse{
		svcmocks.NewMockResponse("application/vnd.api+json", []byte(`{"data": {"id": "test-id"}}`), http.StatusCreated),
		svcmocks.NewMockResponse("application/vnd.api+json", []byte("{}"), http.StatusSeeOther),
		svcmocks.NewMockResponse("application/vnd.api+json", testResultMockResponse, http.StatusOK),
	}

	mockSBOMService := svcmocks.NewMockSBOMServiceMultiResponse(responses, func(r *http.Request) {})
	defer mockSBOMService.Close()
	mockICTX := createMockICTXWithURL(t, mockSBOMService.URL)
	mockICTX.GetConfiguration().Set("experimental", true)
	mockICTX.GetConfiguration().Set("file", "testdata/bom.json")

	result, err := sbomtest.TestWorkflow(mockICTX, []workflow.Data{})

	require.NoError(t, err)

	require.NotNil(t, result)
	assert.Equal(t, len(result), 2)
	data := result[0]
	assert.Equal(t, data.GetContentType(), "text/plain")

	_, ok := data.GetPayload().([]byte)
	assert.True(t, ok)

	summaryData := result[1]
	assert.Equal(t, summaryData.GetContentType(), content_type.TEST_SUMMARY)

	payloadBytes, ok := summaryData.GetPayload().([]byte)
	assert.True(t, ok)
	snapshotter.SnapshotT(t, payloadBytes)
}

func TestSBOMTestWorkflow_SuccessJSON(t *testing.T) {
	responses := []svcmocks.MockResponse{
		svcmocks.NewMockResponse("application/vnd.api+json", []byte(`{"data": {"id": "test-id"}}`), http.StatusCreated),
		svcmocks.NewMockResponse("application/vnd.api+json", []byte("{}"), http.StatusSeeOther),
		svcmocks.NewMockResponse("application/vnd.api+json", testResultMockResponse, http.StatusOK),
	}

	mockSBOMService := svcmocks.NewMockSBOMServiceMultiResponse(responses, func(r *http.Request) {})
	defer mockSBOMService.Close()
	mockICTX := createMockICTXWithURL(t, mockSBOMService.URL)
	mockICTX.GetConfiguration().Set("experimental", true)
	mockICTX.GetConfiguration().Set("file", "testdata/bom.json")
	mockICTX.GetConfiguration().Set("json", true)

	result, err := sbomtest.TestWorkflow(mockICTX, []workflow.Data{})

	require.NoError(t, err)

	require.NotNil(t, result)
	assert.Equal(t, len(result), 2)
	data := result[0]
	assert.Equal(t, data.GetContentType(), "application/json")

	payloadBytes, ok := data.GetPayload().([]byte)
	assert.True(t, ok)
	assert.Contains(t, string(payloadBytes), `"Found 141 issues"`)
	summaryData := result[1]
	assert.Equal(t, summaryData.GetContentType(), content_type.TEST_SUMMARY)

	payloadBytes, ok = summaryData.GetPayload().([]byte)
	assert.True(t, ok)
	snapshotter.SnapshotT(t, payloadBytes)
}

// Helpers

func createMockICTX(t *testing.T) workflow.InvocationContext {
	t.Helper()

	return createMockICTXWithURL(t, "")
}

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
