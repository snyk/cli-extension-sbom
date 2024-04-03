package sbomtest

import (
	"context"
	"fmt"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-sbom/internal/errors"
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
	filename := config.GetString(flags.FlagFile)
	errFactory := errors.NewErrorFactory(logger)
	ctx := context.Background()
	orgID := config.GetString(configuration.ORGANIZATION)
	if orgID == "" {
		return nil, errFactory.NewEmptyOrgError()
	}

	// As this is an experimental feature, we only want to continue if the experimental flag is set
	if !experimental {
		return nil, fmt.Errorf("experimental flag not set")
	}

	if filename == "" {
		return nil, fmt.Errorf("file flag not set")
	}

	bytes, err := ReadSBOMFile(filename)
	if err != nil {
		return nil, err
	}

	logger.Println("SBOM workflow test with file:", filename)

	client := snykclient.NewSnykClient(
		ictx.GetNetworkAccess().GetHttpClient(),
		config.GetString(configuration.API_URL),
		orgID,
	)
	sbomTest, err := client.CreateSBOMTest(ctx, bytes)
	if err != nil {
		return nil, err
	}

	err = sbomTest.WaitUntilComplete(ctx)
	if err != nil {
		return nil, err
	}

	results, err := sbomTest.GetResult(ctx)
	if err != nil {
		return nil, err
	}

	data, contentType, err := newPresenter(ictx).Render(TestResult{
		Summary: TestSummary{
			TotalVulnerabilities: results.Data.Attributes.Summary.TotalVulnerabilities,
		},
	})

	return []workflow.Data{workflowData(data, contentType)}, err
}

func workflowData(data []byte, contentType string) workflow.Data {
	id := workflow.NewTypeIdentifier(WorkflowID, "sbom.test")
	return workflow.NewDataFromInput(nil, id, contentType, data)
}
