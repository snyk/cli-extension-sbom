package sbom_test

import (
	_ "embed"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-sbom/internal/mocks"
	"github.com/snyk/cli-extension-sbom/pkg/sbom"
)

//go:embed testdata/cyclonedx_document.json
var expectedSBOM []byte

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
	mockSBOMService := mocks.NewMockSBOMService(expectedSBOM)
	defer mockSBOMService.Close()
	input := []workflow.Data{}
	ictx := mocks.NewMockInvocationContext(
		mocks.NewMockEngine(),
		mocks.NewMockConfig(mockSBOMService.URL),
	)

	results, err := sbom.SBOMWorkflow(&ictx, input)

	assert.NoError(t, err)
	assert.Len(t, results, 1)
	assert.NotNil(t, results[0])
	sbomBytes, ok := results[0].GetPayload().([]byte)
	assert.True(t, ok)
	assert.Equal(t, string(expectedSBOM), string(sbomBytes))
}
