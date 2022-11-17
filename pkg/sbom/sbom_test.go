package sbom_test

import (
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-sbom/pkg/sbom"
)

func TestInit(t *testing.T) {
	c := configuration.New()
	e := workflow.NewWorkFlowEngine(c)

	err := e.Init()
	assert.NoError(t, err)

	err = sbom.Init(e)
	assert.NoError(t, err)

	// TODO: test the workflow invocation.
	t.Skip()

	_, err = e.Invoke(sbom.WorkflowID)
	assert.NoError(t, err)
}
