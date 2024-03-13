package sbomtest

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

var WorkflowID = workflow.NewWorkflowIdentifier("sbom.test")

func RegisterWorkflows(e workflow.Engine) error {
	sbomFlagset := GetSBOMFlagSet()

	c := workflow.ConfigurationOptionsFromFlagset(sbomFlagset)

	if _, err := e.Register(WorkflowID, c, TestWorkflow); err != nil {
		return fmt.Errorf("error while registering %s workflow: %w", WorkflowID, err)
	}
	return nil
}

func TestWorkflow(
	ictx workflow.InvocationContext,
	_ []workflow.Data,
) ([]workflow.Data, error) {
	config := ictx.GetConfiguration()
	logger := ictx.GetLogger()
	experimental := config.GetBool(SBOMFlagExperimental)
	filename := config.GetString(SBOMFlagFile)

	// As this is an experimental feature, we only want to continue if the experimental flag is set
	if !experimental {
		return nil, fmt.Errorf("experimental flag not set")
	}

	logger.Println("SBOM workflow test with file:", filename)

	return []workflow.Data{}, nil
}
