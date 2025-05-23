package sbomcreate

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-sbom/internal/errors"
	"github.com/snyk/cli-extension-sbom/internal/flags"
	"github.com/snyk/cli-extension-sbom/internal/service"
)

var WorkflowID = workflow.NewWorkflowIdentifier("sbom")

func RegisterWorkflows(e workflow.Engine) error {
	flagset := flags.GetSBOMCreateFlagSet()

	c := workflow.ConfigurationOptionsFromFlagset(flagset)

	if _, err := e.Register(WorkflowID, c, SBOMWorkflow); err != nil {
		return fmt.Errorf("error while registering SBOM workflow: %w", err)
	}

	return nil
}

func SBOMWorkflow(
	ictx workflow.InvocationContext,
	_ []workflow.Data,
) ([]workflow.Data, error) {
	config := ictx.GetConfiguration()
	logger := ictx.GetEnhancedLogger()
	format := config.GetString(flags.FlagFormat)
	version := config.GetString(flags.FlagVersion)
	errFactory := errors.NewErrorFactory(logger)

	logger.Println("SBOM workflow start")

	if err := service.ValidateSBOMFormat(errFactory, format); err != nil {
		return nil, err
	}

	logger.Println("Getting preferred organization ID")

	orgID := config.GetString(configuration.ORGANIZATION)
	if orgID == "" {
		return nil, errFactory.NewEmptyOrgError()
	}

	depGraphResult, err := GetDepGraph(ictx)
	if err != nil {
		return nil, err
	}

	ri := ictx.GetRuntimeInfo()

	result, err := service.DepGraphsToSBOM(
		ictx.GetNetworkAccess().GetHttpClient(),
		config.GetString(configuration.API_URL),
		orgID,
		depGraphResult.DepGraphBytes,
		service.NewSubject(depGraphResult.Name, version),
		&service.Tool{Vendor: "Snyk", Name: ri.GetName(), Version: ri.GetVersion()},
		format,
		logger,
		errFactory,
	)
	if err != nil {
		return nil, err
	}

	sbomDoc := []workflow.Data{newWorkflowData(nil, result.MIMEType, result.Doc)}

	logger.Print("Successfully generated SBOM document.\n")

	return sbomDoc, nil
}

func newWorkflowData(depGraph workflow.Data, contentType string, sbom []byte) workflow.Data {
	// TODO: refactor to workflow.NewData()
	//nolint:staticcheck // Silencing since we are only upgrading the GAF to remediate a vuln.
	return workflow.NewDataFromInput(
		depGraph,
		workflow.NewTypeIdentifier(WorkflowID, "sbom"),
		contentType,
		sbom,
	)
}
