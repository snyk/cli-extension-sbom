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

	logger.Println("SBOM Test workflow start")

	// As this is an experimental feature, we only want to continue if the experimental flag is set
	if !experimental {
		return nil, fmt.Errorf("experimental flag not set")
	}

	logger.Println("Getting preferred organization ID")

	orgID := config.GetString(configuration.ORGANIZATION)
	if orgID == "" {
		return nil, errFactory.NewEmptyOrgError()
	}

	if filename == "" {
		return nil, fmt.Errorf("file flag not set")
	}

	logger.Println("Target SBOM document:", filename)

	bytes, err := ReadSBOMFile(filename)
	if err != nil {
		return nil, err
	}

	client := snykclient.NewSnykClient(
		ictx.GetNetworkAccess().GetHttpClient(),
		config.GetString(configuration.API_URL),
		orgID,
	)
	sbomTest, err := client.CreateSBOMTest(ctx, bytes)
	if err != nil {
		return nil, err
	}

	logger.Printf("Created SBOM test (ID %s), waiting for results...\n", sbomTest.ID)

	err = sbomTest.WaitUntilComplete(ctx)
	if err != nil {
		return nil, err
	}

	logger.Print("Test complete, fetching results")

	results, err := sbomTest.GetResult(ctx)
	if err != nil {
		return nil, err
	}

	data, contentType, err := NewPresenter(ictx).Render(TestResult{
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
