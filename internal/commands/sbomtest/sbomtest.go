package sbomtest

import (
	"bytes"
	"context"
	stderrors "errors"
	"fmt"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
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
		return nil, errFactory.NewMissingExperimentalFlagError()
	}

	logger.Println("Getting preferred organization ID")

	orgID := config.GetString(configuration.ORGANIZATION)
	if orgID == "" {
		return nil, errFactory.NewEmptyOrgError()
	}

	if filename == "" {
		return nil, errFactory.NewMissingFilenameFlagError()
	}

	logger.Println("Target SBOM document:", filename)

	bts, err := ReadSBOMFile(filename, errFactory)
	if err != nil {
		return nil, err
	}

	client := snykclient.NewSnykClient(
		ictx.GetNetworkAccess().GetHttpClient(),
		config.GetString(configuration.API_URL),
		orgID,
	)
	sbomTest, err := client.CreateSBOMTest(ctx, bts, errFactory)
	if err != nil {
		return nil, err
	}

	logger.Printf("Created SBOM test (ID %s), waiting for results...\n", sbomTest.ID)

	err = sbomTest.WaitUntilComplete(ctx, errFactory)
	if err != nil {
		var snykErr snyk_errors.Error
		if stderrors.As(err, &snykErr) {
			return nil, snykErr
		}
		return nil, err
	}

	logger.Print("Test complete, fetching results")

	results, err := sbomTest.GetResult(ctx, errFactory)
	if err != nil {
		return nil, err
	}

	var ct string
	var buf bytes.Buffer

	if ictx.GetConfiguration().GetBool("json") {
		if err := RenderJSONResult(&buf, results); err != nil { //nolint:govet // Shadowing err symbol not an issue.
			return nil, errFactory.NewFatalSBOMTestError(err)
		}
		ct = MIMETypeJSON
	} else {
		if err := RenderPrettyResult(&buf, orgID, filename, results); err != nil { //nolint:govet // Shadowing err symbol not an issue.
			return nil, errFactory.NewFatalSBOMTestError(err)
		}
		ct = MIMETypeText
	}

	summaryData, summaryContentType, err := BuildTestSummary(results.Summary)
	if err != nil {
		return nil, errFactory.NewFatalSBOMTestError(err)
	}

	return []workflow.Data{workflowData(buf.Bytes(), ct), workflowData(summaryData, summaryContentType)}, err
}

func workflowData(data []byte, contentType string) workflow.Data {
	id := workflow.NewTypeIdentifier(WorkflowID, "sbom.test")
	// TODO: refactor to workflow.NewData()
	//nolint:staticcheck // Silencing since we are only upgrading the GAF to remediate a vuln.
	return workflow.NewDataFromInput(nil, id, contentType, data)
}
