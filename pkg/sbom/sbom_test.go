package sbom_test

import (
	"net/url"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-sbom/internal/commands/sbomcreate"
	"github.com/snyk/cli-extension-sbom/internal/commands/sbomtest"
	"github.com/snyk/cli-extension-sbom/pkg/sbom"
)

func TestInit(t *testing.T) {
	c := configuration.New()
	e := workflow.NewWorkFlowEngine(c)

	err := e.Init()
	assert.NoError(t, err)

	err = sbom.Init(e)
	assert.NoError(t, err)

	assertWorkflowExists(t, e, sbomcreate.WorkflowID)
	assertWorkflowExists(t, e, sbomtest.WorkflowID)
}

func assertWorkflowExists(t *testing.T, e workflow.Engine, id *url.URL) {
	t.Helper()

	wflw, ok := e.GetWorkflow(id)
	assert.True(t, ok)
	assert.NotNil(t, wflw)
}
