package sbom

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-sbom/internal/errors"
	"github.com/snyk/cli-extension-sbom/internal/flags"
	"github.com/snyk/cli-extension-sbom/internal/service"
)

var (
	WorkflowID         = workflow.NewWorkflowIdentifier("sbom")
	DepGraphWorkflowID = workflow.NewWorkflowIdentifier("depgraph")
)

func SBOMWorkflow(
	ictx workflow.InvocationContext,
	_ []workflow.Data,
) ([]workflow.Data, error) {
	engine := ictx.GetEngine()
	config := ictx.GetConfiguration()
	logger := ictx.GetLogger()
	format := config.GetString(flags.FlagFormat)
	name := config.GetString(flags.FlagName)
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

	logger.Println("Invoking depgraph workflow")

	depGraphs, err := engine.Invoke(DepGraphWorkflowID)
	if err != nil {
		return nil, errFactory.NewDepGraphWorkflowError(err)
	}

	numGraphs := len(depGraphs)
	logger.Printf("Generating documents for %d depgraph(s)\n", numGraphs)
	depGraphsBytes := make([][]byte, numGraphs)
	for i, depGraph := range depGraphs {
		depGraphBytes, err := getPayloadBytes(depGraph) //nolint:govet // error is checked
		if err != nil {
			return nil, errFactory.NewInternalError(err)
		}
		depGraphsBytes[i] = depGraphBytes
	}
	if numGraphs > 1 {
		if name == "" {
			// Fall back to current working directory
			wd, err := os.Getwd() //nolint:govet // error is checked
			if err != nil {
				return nil, errFactory.NewDepGraphWorkflowError(err)
			}
			name = filepath.Base(wd)
		}
		logger.Printf("Document subject: { Name: %q, Version: %q }\n", name, version)
	}

	result, err := service.DepGraphsToSBOM(
		ictx.GetNetworkAccess().GetHttpClient(),
		config.GetString(configuration.API_URL),
		orgID,
		depGraphsBytes,
		service.NewSubject(name, version),
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

func Init(e workflow.Engine) error {
	flagset := flags.GetFlagSet()

	c := workflow.ConfigurationOptionsFromFlagset(flagset)

	if _, err := e.Register(WorkflowID, c, SBOMWorkflow); err != nil {
		return fmt.Errorf("error while registering SBOM workflow: %w", err)
	}

	return nil
}

func newWorkflowData(depGraph workflow.Data, contentType string, sbom []byte) workflow.Data {
	return workflow.NewDataFromInput(
		depGraph,
		workflow.NewTypeIdentifier(WorkflowID, "sbom"),
		contentType,
		sbom,
	)
}

func getPayloadBytes(data workflow.Data) ([]byte, error) {
	payload := data.GetPayload()
	bytes, ok := payload.([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid payload type (want []byte, got %T)", payload)
	}
	return bytes, nil
}
