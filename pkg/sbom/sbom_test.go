package sbom_test

import (
	_ "embed"
	"io"
	"log"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"

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
	mockICTX := mockInvocationContext(ctrl, mockSBOMService.URL)

	results, err := sbom.SBOMWorkflow(mockICTX, []workflow.Data{})

	assert.NoError(t, err)
	assert.Len(t, results, 1)
	assert.NotNil(t, results[0])
	sbomBytes, ok := results[0].GetPayload().([]byte)
	assert.True(t, ok)
	assert.Equal(t, string(expectedSBOM), string(sbomBytes))
}

func TestSBOMWorkflow_NoExperimentalFlag(t *testing.T) {
	mockLogger := log.New(io.Discard, "", 0)
	ctrl := gomock.NewController(t)
	mockConfig := mocks.NewMockConfiguration(ctrl)
	mockConfig.EXPECT().GetBool(gomock.Any()).Return(false).AnyTimes()
	mockConfig.EXPECT().GetString(gomock.Any()).Return("").AnyTimes()
	mockEngine := mocks.NewMockEngine(ctrl)
	mockICTX := mocks.NewMockInvocationContext(ctrl)
	mockICTX.EXPECT().GetConfiguration().Return(mockConfig)
	mockICTX.EXPECT().GetEngine().Return(mockEngine)
	mockICTX.EXPECT().GetLogger().Return(mockLogger)

	_, err := sbom.SBOMWorkflow(mockICTX, []workflow.Data{})

	assert.ErrorContains(t, err, "Must set `--experimental` flag to enable sbom command.")
}

func TestSBOMWorkflow_EmptyFormat(t *testing.T) {
	mockLogger := log.New(io.Discard, "", 0)
	ctrl := gomock.NewController(t)
	mockConfig := mocks.NewMockConfiguration(ctrl)
	mockConfig.EXPECT().GetBool(gomock.Any()).Return(true).AnyTimes()
	mockConfig.EXPECT().GetString("format").Return("").AnyTimes()
	mockEngine := mocks.NewMockEngine(ctrl)
	mockICTX := mocks.NewMockInvocationContext(ctrl)
	mockICTX.EXPECT().GetConfiguration().Return(mockConfig)
	mockICTX.EXPECT().GetEngine().Return(mockEngine)
	mockICTX.EXPECT().GetLogger().Return(mockLogger)

	_, err := sbom.SBOMWorkflow(mockICTX, []workflow.Data{})

	assert.ErrorContains(t, err, "Must set `--format` flag to specify an SBOM format.")
}

func TestSBOMWorkflow_InvalidFOrmat(t *testing.T) {
	mockLogger := log.New(io.Discard, "", 0)
	ctrl := gomock.NewController(t)
	mockConfig := mocks.NewMockConfiguration(ctrl)
	mockConfig.EXPECT().GetBool(gomock.Any()).Return(true).AnyTimes()
	mockConfig.EXPECT().GetString("format").Return("cyclonedx+json").AnyTimes()
	mockEngine := mocks.NewMockEngine(ctrl)
	mockICTX := mocks.NewMockInvocationContext(ctrl)
	mockICTX.EXPECT().GetConfiguration().Return(mockConfig)
	mockICTX.EXPECT().GetEngine().Return(mockEngine)
	mockICTX.EXPECT().GetLogger().Return(mockLogger)

	_, err := sbom.SBOMWorkflow(mockICTX, []workflow.Data{})

	assert.ErrorContains(t, err, "The format provided (cyclonedx+json) is not one of the available formats. "+
		"Available formats are: cyclonedx1.4+json, cyclonedx1.4+xml, spdx2.3+json")
}

func TestSBOMWorkflow_InvalidPayload(t *testing.T) {
	mockLogger := log.New(io.Discard, "", 0)
	ctrl := gomock.NewController(t)
	mockConfig := mocks.NewMockConfiguration(ctrl)
	mockConfig.EXPECT().GetBool(gomock.Any()).Return(true).AnyTimes()
	mockConfig.EXPECT().GetString("format").Return("cyclonedx1.4+json").AnyTimes()
	mockEngine := mocks.NewMockEngine(ctrl)
	mockEngine.EXPECT().Invoke(gomock.Eq(sbom.DepGraphWorkflowID)).Return([]workflow.Data{
		workflow.NewData(workflow.NewTypeIdentifier(sbom.DepGraphWorkflowID, "cyclonedx"), "application/json", nil),
	}, nil)
	mockICTX := mocks.NewMockInvocationContext(ctrl)
	mockICTX.EXPECT().GetConfiguration().Return(mockConfig)
	mockICTX.EXPECT().GetEngine().Return(mockEngine)
	mockICTX.EXPECT().GetLogger().Return(mockLogger)

	_, err := sbom.SBOMWorkflow(mockICTX, nil)

	assert.ErrorContains(t, err, "An error occurred while running the underlying analysis which is required to generate the SBOM. "+
		"Should this issue persist, please reach out to customer support.")
}

func mockInvocationContext(ctrl *gomock.Controller, sbomServiceURL string) workflow.InvocationContext {
	mockLogger := log.New(io.Discard, "", 0)

	mockConfig := mocks.NewMockConfiguration(ctrl)
	mockConfig.EXPECT().GetString(gomock.Any()).DoAndReturn(func(key string) string {
		switch key {
		case configuration.AUTHENTICATION_TOKEN:
			return "<SOME API TOKEN>"
		case configuration.ORGANIZATION:
			return "6277734c-fc84-4c74-9662-33d46ec66c53"
		case configuration.API_URL:
			return sbomServiceURL
		case "format":
			return "cyclonedx1.4+json"
		default:
			return ""
		}
	}).AnyTimes()
	mockConfig.EXPECT().GetBool(gomock.Any()).Return(true).AnyTimes()
	mockConfig.EXPECT().GetInt(gomock.Any()).Return(0).AnyTimes()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockEngine.EXPECT().Invoke(gomock.Eq(sbom.DepGraphWorkflowID)).Return([]workflow.Data{
		workflow.NewData(workflow.NewTypeIdentifier(sbom.DepGraphWorkflowID, "cyclonedx"), "application/json", depGraphData),
	}, nil)

	ictx := mocks.NewMockInvocationContext(ctrl)
	ictx.EXPECT().GetConfiguration().Return(mockConfig)
	ictx.EXPECT().GetEngine().Return(mockEngine)
	ictx.EXPECT().GetNetworkAccess().Return(networking.NewNetworkAccess(mockConfig))
	ictx.EXPECT().GetLogger().Return(mockLogger)

	return ictx
}
