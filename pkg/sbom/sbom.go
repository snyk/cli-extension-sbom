package sbom

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"

	"github.com/snyk/cli-extension-sbom/internal/service"
	"github.com/snyk/cli-extension-sbom/pkg/workflowerrors"
)

var (
	WorkflowID         = workflow.NewWorkflowIdentifier("sbom")
	DepGraphWorkflowID = workflow.NewWorkflowIdentifier("depgraph")
)

const (
	flagExperimental = "experimental"
	flagUnmanaged    = "unmanaged"
	flagFile         = "file"
	flagFormat       = "format"
)

func SBOMWorkflow(
	ictx workflow.InvocationContext,
	_ []workflow.Data,
) (sbomDocs []workflow.Data, err error) {
	engine := ictx.GetEngine()
	config := ictx.GetConfiguration()
	logger := ictx.GetLogger()
	format := config.GetString(flagFormat)
	orgID := config.GetString(configuration.ORGANIZATION)

	logger.Println("SBOM workflow start")

	if !config.GetBool(flagExperimental) {
		return nil, workflowerrors.NewExperimentalFlagError()
	}

	if orgID == "" {
		return nil, workflowerrors.NewEmptyOrgIDError()
	}

	logger.Println("Invoking depgraph workflow")

	depGraphs, err := engine.Invoke(DepGraphWorkflowID)
	if err != nil {
		return nil, err
	}

	logger.Printf("Generating documents for %d depgraph(s)\n", len(depGraphs))

	for _, depGraph := range depGraphs {
		depGraphBytes, err := getPayloadBytes(depGraph)
		if err != nil {
			return nil, workflowerrors.NewFailedSCAError(err)
		}

		sbomBytes, err := service.DepGraphToSBOM(
			ictx.GetNetworkAccess().GetHttpClient(),
			config.GetString(configuration.API_URL),
			orgID,
			depGraphBytes,
			format,
			logger,
		)
		if err != nil {
			return nil, workflowerrors.NewFailedConversionError(err)
		}

		sbomDocs = append(sbomDocs, newData(depGraph, service.MimeTypeCycloneDXJSON, sbomBytes))
	}

	logger.Printf("Successfully generated %d document(s}\n", len(sbomDocs))

	return sbomDocs, nil
}

func Init(e workflow.Engine) error {
	flagset := pflag.NewFlagSet("snyk-cli-extension-sbom", pflag.ExitOnError)

	flagset.Bool(flagExperimental, false, "Explicitly enable `sbom` command with the --experimental flag.")
	flagset.Bool(flagUnmanaged, false, "For C/C++ only, scan all files for known open source dependencies and build an SBOM.")
	flagset.String(flagFile, "", "Specify a package file.")
	flagset.StringP(flagFormat, "f", "cyclonedx1.4+json", "Specify the SBOM output format. (cyclonedx1.4+json, cyclonedx1.4+xml, spdx2.3+json)")

	c := workflow.ConfigurationOptionsFromFlagset(flagset)

	if _, err := e.Register(WorkflowID, c, SBOMWorkflow); err != nil {
		return fmt.Errorf("error while registering SBOM workflow: %w", err)
	}

	return nil
}

func newData(depGraph workflow.Data, contentType string, sbom []byte) workflow.Data {
	return workflow.NewDataFromInput(
		depGraph,
		workflow.NewTypeIdentifier(WorkflowID, "cyclonedx"),
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
