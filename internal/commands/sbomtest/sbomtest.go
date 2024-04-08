package sbomtest

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-sbom/internal/flags"
	"github.com/snyk/cli-extension-sbom/internal/snykclient"
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
	printDeps := config.GetBool(flags.FlagPrintDeps)
	filename := config.GetString(flags.FlagFile)

	// As this is an experimental feature, we only want to continue if the experimental flag is set
	if !experimental {
		return nil, fmt.Errorf("experimental flag not set")
	}

	logger.Println("SBOM workflow test with file:", filename)

	fd, err := os.Open(filename)
	if err != nil {
		panic(err)
	}

	var body snykclient.GetSBOMTestResultResponseBody

	err = json.NewDecoder(fd).Decode(&body)
	if err != nil {
		panic(err)
	}

	/*
		mockResult := snykclient.GetSBOMTestResultResponseBody{ // TODO: assign the actual test result
			Data: &snykclient.GetSBOMTestResultResponseData{
				Attributes: snykclient.SBOMTestRunAttributes{
					Summary: snykclient.SBOMTestRunSummary{
						TotalIssues:          42,
						TotalVulnerabilities: 42,
						TotalLicenseIssues:   0,
					},
				},
			},
		}
	*/

	data, contentType, err := newPresenter(ictx).Render(filename, &body, printDeps)

	return []workflow.Data{workflowData(data, contentType)}, err
}

func workflowData(data []byte, contentType string) workflow.Data {
	id := workflow.NewTypeIdentifier(WorkflowID, "sbom.test")
	return workflow.NewDataFromInput(nil, id, contentType, data)
}
