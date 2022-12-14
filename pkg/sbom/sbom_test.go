package sbom_test

import (
	_ "embed"
	"io"
	"log"
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

func TestSBOMWorkflowSuccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockSBOMService := svcmocks.NewMockSBOMService(expectedSBOM)
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
