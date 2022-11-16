package sbom

import (
	"net/url"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
)

func TestInit(t *testing.T) {
	c := configuration.New()
	e := workflow.NewWorkFlowEngine(c)

	err := e.Init()
	assert.NoError(t, err)

	err = Init(e)
	assert.NoError(t, err)

	WorkflowID, _ := url.Parse(OutputWorkflowScheme)

	_, err = e.Invoke(WorkflowID)
	assert.NoError(t, err)
}
