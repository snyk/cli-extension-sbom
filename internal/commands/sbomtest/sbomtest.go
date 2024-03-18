package sbomtest

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-sbom/internal/flags"
)

var WorkflowID = workflow.NewWorkflowIdentifier("sbom.test")

func RegisterWorkflows(e workflow.Engine) error {
	sbomFlagset := flags.GetSBOMTestFlagSet()

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
	experimental := config.GetBool(flags.FlagExperimental)
	filename := config.GetString(flags.FlagFile)

	// As this is an experimental feature, we only want to continue if the experimental flag is set
	if !experimental {
		return nil, fmt.Errorf("experimental flag not set")
	}

	logger.Println("SBOM workflow test with file:", filename)

	mockResult := TestResult{ // TODO: assign the actual test result
		Summary: TestSummary{TotalVulnerabilities: 42},
	}
	data, contentType, err := newPresenter(ictx).Render(mockResult)

	return []workflow.Data{workflowData(data, contentType)}, err
}

func workflowData(data []byte, contentType string) workflow.Data {
	id := workflow.NewTypeIdentifier(WorkflowID, "sbom.test")
	return workflow.NewDataFromInput(nil, id, contentType, data)
}
