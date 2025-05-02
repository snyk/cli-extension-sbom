package sbomtest

import (
	"bytes"
	"context"
	stderrors "errors"
	"fmt"

	"github.com/rs/zerolog"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-sbom/internal/bundlestore"
	"github.com/snyk/cli-extension-sbom/internal/errors"
	"github.com/snyk/cli-extension-sbom/internal/flags"
	"github.com/snyk/cli-extension-sbom/internal/sbom"
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
	logger := ictx.GetEnhancedLogger()
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

	isReachabilityEnabled := config.GetBool("INTERNAL_SNYK_DEV_REACHABILITY")
	if isReachabilityEnabled {
		return sbomTestReachability(ctx, config, ictx, logger, filename)
	} else {
		return sbomTest(ctx, filename, errFactory, ictx, config, orgID, logger)
	}
}

func sbomTest(
	ctx context.Context,
	filename string,
	errFactory *errors.ErrorFactory,
	ictx workflow.InvocationContext,
	config configuration.Configuration,
	orgID string,
	logger *zerolog.Logger,
) ([]workflow.Data, error) {
	bts, err := sbom.ReadSBOMFile(filename, errFactory)
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

func sbomTestReachability(
	ctx context.Context,
	config configuration.Configuration,
	ictx workflow.InvocationContext,
	logger *zerolog.Logger,
	sbomPath string,
) ([]workflow.Data, error) {
	bsc := bundlestore.NewClient(config, ictx.GetNetworkAccess().GetHttpClient, logger)

	sbomBundleHash, err := bsc.UploadSBOM(ctx, sbomPath)
	if err != nil {
		logger.Error().Err(err).Str("sbomPath", sbomPath).Msg("Failed to upload SBOM")
		return nil, err
	}
	logger.Println("sbomBundleHash", sbomBundleHash)

	sourceCodePath := "." // TODO: pass in configurable source code dir to this func
	sourceCodeBundleHash, err := bsc.UploadSourceCode(ctx, sourceCodePath)
	if err != nil {
		logger.Error().Err(err).Str("sourceCodePath", sourceCodePath).Msg("Failed to upload SBOM")
		return nil, err
	}
	logger.Println("sourceCodeBundleHash", sourceCodeBundleHash)

	return nil, nil // TODO: return something meaningful once this function is complete
}

func workflowData(data []byte, contentType string) workflow.Data {
	id := workflow.NewTypeIdentifier(WorkflowID, "sbom.test")
	// TODO: refactor to workflow.NewData()
	//nolint:staticcheck // Silencing since we are only upgrading the GAF to remediate a vuln.
	return workflow.NewDataFromInput(nil, id, contentType, data)
}
