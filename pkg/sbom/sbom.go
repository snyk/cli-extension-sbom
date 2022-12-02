package sbom

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"

	"github.com/snyk/cli-extension-sbom/internal/service"
)

var (
	WorkflowID         = workflow.NewWorkflowIdentifier("sbom")
	DepGraphWorkflowID = workflow.NewWorkflowIdentifier("depgraph")
)

func SBOMWorkflow(
	ictx workflow.InvocationContext,
	_ []workflow.Data,
) (sbomDocs []workflow.Data, err error) {
	engine := ictx.GetEngine()
	config := ictx.GetConfiguration()

	depGraphs, err := engine.Invoke(DepGraphWorkflowID)
	if err != nil {
		return nil, err
	}

	for _, depGraph := range depGraphs {
		depGraphBytes, err := getPayloadBytes(depGraph)
		if err != nil {
			return nil, err
		}

		sbomBytes, err := service.DepGraphToSBOM(
			ictx.GetNetworkAccess().GetHttpClient(),
			config.GetString(configuration.API_URL),
			config.GetString(configuration.ORGANIZATION),
			depGraphBytes,
			service.SBOMFormatCycloneDXJSON,
		)
		if err != nil {
			return nil, err
		}

		sbomDocs = append(sbomDocs, newData(depGraph, service.MimeTypeCycloneDXJSON, sbomBytes))
	}

	return sbomDocs, nil
}

func Init(e workflow.Engine) error {
	flagset := pflag.NewFlagSet("snyk-cli-extension-sbom", pflag.ExitOnError)
	// TODO: add proper user documentation.
	flagset.String("file", "", "usage docs for file option")
	// TODO: add proper user documentation.
	flagset.StringP("format", "f", "text", "usage docs for format option")

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
