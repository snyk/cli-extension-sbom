package sbom_test

import (
	_ "embed"
	"errors"
	"io"
	"log"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	svcmocks "github.com/snyk/cli-extension-sbom/internal/mocks"
	"github.com/snyk/cli-extension-sbom/pkg/sbom"
)

//go:embed testdata/cyclonedx_document.json
var expectedSBOM []byte

//go:embed testdata/depgraph.json
var depGraphData []byte

func TestInit(t *testing.T) {
	c := configuration.New()
	e := workflow.NewWorkFlowEngine(c)

	err := e.Init()
	assert.NoError(t, err)

	err = sbom.Init(e)
	assert.NoError(t, err)

	wflw, ok := e.GetWorkflow(sbom.WorkflowID)
	assert.True(t, ok)
	assert.NotNil(t, wflw)
}

func TestSBOMWorkflow_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockResponse := svcmocks.NewMockResponse("application/vnd.cyclonedx+json", expectedSBOM, http.StatusOK)
	mockSBOMService := svcmocks.NewMockSBOMService(mockResponse)
	defer mockSBOMService.Close()
	mockICTX := mockInvocationContext(t, ctrl, mockSBOMService.URL, nil)

	results, err := sbom.SBOMWorkflow(mockICTX, []workflow.Data{})

	assert.NoError(t, err)
	assert.Len(t, results, 1)
	assert.NotNil(t, results[0])
	sbomBytes, ok := results[0].GetPayload().([]byte)
	assert.True(t, ok)
	assert.Equal(t, string(expectedSBOM), string(sbomBytes))
}

func TestSBOMWorkflow_EmptyFormat(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockICTX := mockInvocationContext(t, ctrl, "", nil)
	mockICTX.GetConfiguration().Set("format", "")

	_, err := sbom.SBOMWorkflow(mockICTX, []workflow.Data{})

	assert.ErrorContains(t, err, "Must set `--format` flag to specify an SBOM format.")
}

func TestSBOMWorkflow_InvalidFormat(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockICTX := mockInvocationContext(t, ctrl, "", nil)
	mockICTX.GetConfiguration().Set("format", "cyclonedx+json")

	_, err := sbom.SBOMWorkflow(mockICTX, []workflow.Data{})

	assert.ErrorContains(t, err, "The format provided (cyclonedx+json) is not one of the available formats. "+
		"Available formats are: cyclonedx1.4+json, cyclonedx1.4+xml, cyclonedx1.5+json, cyclonedx1.5+xml, spdx2.3+json")
}

func TestSBOMWorkflow_NoOrgID(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockICTX := mockInvocationContext(t, ctrl, "", nil)
	mockICTX.GetConfiguration().Set(configuration.ORGANIZATION, "")

	_, err := sbom.SBOMWorkflow(mockICTX, []workflow.Data{})

	assert.ErrorContains(t, err, "Snyk failed to infer an organization ID. Please make sure to authenticate using `snyk auth`. "+
		"Should the issue persist, explicitly set an organization ID via the `--org` flag.")
}

func TestSBOMWorkflow_InvalidPayload(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockEngine := newMockEngine(
		ctrl,
		[]workflow.Data{workflow.NewData(workflow.NewTypeIdentifier(sbom.DepGraphWorkflowID, "cyclonedx"), "application/json", nil)},
		nil,
	)
	mockICTX := mockInvocationContext(t, ctrl, "", mockEngine)

	_, err := sbom.SBOMWorkflow(mockICTX, nil)

	assert.ErrorContains(t, err, "An error occurred while running the underlying analysis which is required to generate the SBOM. "+
		"Should this issue persist, please reach out to customer support.")
}

func TestSBOMWorkflow_DepGraphError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockEngine := newMockEngine(ctrl, nil, errors.New("error during composition analysis"))
	mockICTX := mockInvocationContext(t, ctrl, "", mockEngine)

	_, err := sbom.SBOMWorkflow(mockICTX, []workflow.Data{})

	assert.ErrorContains(t, err, "An error occurred while running the underlying analysis needed to generate the SBOM.")
}

func TestSBOMWorkflow_MultipleDepGraphs(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockResponse := svcmocks.NewMockResponse("application/vnd.cyclonedx+json", []byte("{}"), http.StatusOK)
	mockSBOMService := svcmocks.NewMockSBOMService(mockResponse, func(r *http.Request) {
		body, err := io.ReadAll(r.Body)
		defer r.Body.Close()
		require.NoError(t, err)
		assert.JSONEq(t, `{"depGraphs":[{"pkgManager":{"name":"npm"}},{"pkgManager":{"name":"nuget"}}],`+
			`"subject":{"name":"goof","version":"0.0.0"},`+
			`"tools":[{"name":"test-app","vendor":"Snyk","version":"1.2.3"}]}`,
			string(body))
	})
	defer mockSBOMService.Close()
	mockEngine := newMockEngine(ctrl, []workflow.Data{
		newDepGraphData(t, []byte(`{"pkgManager":{"name":"npm"}}`)),
		newDepGraphData(t, []byte(`{"pkgManager":{"name":"nuget"}}`)),
	}, nil)
	mockICTX := mockInvocationContext(t, ctrl, mockSBOMService.URL, mockEngine)

	results, err := sbom.SBOMWorkflow(mockICTX, []workflow.Data{})

	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.NotNil(t, results[0])
	sbomBytes, ok := results[0].GetPayload().([]byte)
	assert.True(t, ok)
	assert.JSONEq(t, "{}", string(sbomBytes))
}

func TestSBOMWorkflow_MergeSubject(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockResponse := svcmocks.NewMockResponse("application/vnd.cyclonedx+json", []byte("{}"), http.StatusOK)
	mockSBOMService := svcmocks.NewMockSBOMService(mockResponse, func(r *http.Request) {
		body, err := io.ReadAll(r.Body)
		defer r.Body.Close()
		require.NoError(t, err)
		assert.JSONEq(t, `{"depGraphs":[{},{}],"subject":{"name":"sbom","version":""},`+
			`"tools":[{"name":"test-app","vendor":"Snyk","version":"1.2.3"}]}`,
			string(body),
			"Fall back to working directory name.")
	})
	defer mockSBOMService.Close()
	mockEngine := newMockEngine(ctrl, []workflow.Data{newDepGraphData(t, []byte(`{}`)), newDepGraphData(t, []byte(`{}`))}, nil)
	mockICTX := mockInvocationContext(t, ctrl, mockSBOMService.URL, mockEngine)
	mockICTX.GetConfiguration().Set("name", "")
	mockICTX.GetConfiguration().Set("version", "")

	_, err := sbom.SBOMWorkflow(mockICTX, []workflow.Data{})
	require.NoError(t, err)
}

func mockInvocationContext(
	t *testing.T,
	ctrl *gomock.Controller,
	sbomServiceURL string,
	mockEngine *mocks.MockEngine,
) workflow.InvocationContext {
	t.Helper()

	mockLogger := log.New(io.Discard, "", 0)

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

	if mockEngine == nil {
		mockEngine = newMockEngine(
			ctrl,
			[]workflow.Data{newDepGraphData(t, depGraphData)},
			nil,
		)
	}

	ictx := mocks.NewMockInvocationContext(ctrl)
	ictx.EXPECT().GetConfiguration().Return(mockConfig).AnyTimes()
	ictx.EXPECT().GetEngine().Return(mockEngine).AnyTimes()
	ictx.EXPECT().GetNetworkAccess().Return(networking.NewNetworkAccess(mockConfig)).AnyTimes()
	ictx.EXPECT().GetLogger().Return(mockLogger).AnyTimes()
	ictx.EXPECT().GetRuntimeInfo().Return(mockRuntimeInfo).AnyTimes()

	return ictx
}

func newMockEngine(ctrl *gomock.Controller, result []workflow.Data, err error) *mocks.MockEngine {
	mockEngine := mocks.NewMockEngine(ctrl)

	mockEngine.
		EXPECT().
		InvokeWithConfig(gomock.Eq(sbom.DepGraphWorkflowID), gomock.Any()).
		Return(result, err).
		AnyTimes()

	return mockEngine
}

func newDepGraphData(t *testing.T, bts []byte) workflow.Data {
	t.Helper()

	return workflow.NewData(
		workflow.NewTypeIdentifier(sbom.DepGraphWorkflowID, "cyclonedx"),
		"application/json",
		bts,
	)
}
