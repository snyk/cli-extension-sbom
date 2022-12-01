package sbom

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
)

const (
	apiVersion              = "2022-03-31~experimental"
	mimeTypeCycloneDXJSON   = "application/vnd.cyclonedx+json"
	sbomFormatCycloneDXJSON = "cyclonedx+json"
)

var (
	WorkflowID         = workflow.NewWorkflowIdentifier("sbom")
	DepGraphWorkflowID = workflow.NewWorkflowIdentifier("depgraph")
)

func SBOMWorkflow(
	ictx workflow.InvocationContext,
	input []workflow.Data,
) (sbomList []workflow.Data, err error) {
	var workflowEngineInstance = ictx.GetEngine()

	depGraphs, err := workflowEngineInstance.Invoke(DepGraphWorkflowID)
	if err != nil {
		return sbomList, err
	}

	for _, depGraph := range depGraphs {
		depGraphPayload := depGraph.GetPayload()
		depGraphBytes, ok := depGraphPayload.([]byte)
		if !ok {
			return nil, fmt.Errorf("invalid dep graph type for SBOM conversion (want []byte, got %T)", depGraphPayload)
		}

		sbom, err := convertDepGraphToSBOM(
			ictx,
			depGraphBytes,
			sbomFormatCycloneDXJSON,
		)
		if err != nil {
			return nil, err
		}

		sbomList = append(sbomList, workflow.NewDataFromInput(
			depGraph,
			WorkflowID,
			mimeTypeCycloneDXJSON,
			sbom,
		))
	}

	return sbomList, nil
}

func convertDepGraphToSBOM(
	ictx workflow.InvocationContext,
	depGraph []byte,
	format string,
) (sbom []byte, err error) {
	config := ictx.GetConfiguration()

	orgID := config.GetString(configuration.ORGANIZATION)
	apiURL := config.GetString(configuration.API_URL)

	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		fmt.Sprintf(
			"%s/hidden/orgs/%s/sbom?version=%s&format=%s",
			apiURL, orgID, apiVersion, url.QueryEscape(format),
		),
		bytes.NewBuffer([]byte(fmt.Sprintf(`{"depGraph":%s}`, depGraph))),
	)
	if err != nil {
		return nil, fmt.Errorf("error while creating request: %w", err)
	}
	network := networking.NewNetworkAccess(config)
	network.AddHeaderField("Content-Type", "application/json")
	client := network.GetHttpClient()

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error while making request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("could not convert to SBOM (status: %s)", resp.Status)
	}

	if resp.Header.Get("Content-Type") != mimeTypeCycloneDXJSON {
		return nil, errors.New("received unexpected response format")
	}

	defer resp.Body.Close()
	sbom, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read response body: %w", err)
	}

	return sbom, nil
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
