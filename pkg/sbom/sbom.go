package sbom

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
)

const SBOMWorkflowScheme = "flw://sbom"
const DepGraphWorkflowScheme = "flw://depgraph"
// TODO: need to check with Peter S. if this URL scheme is correct
const OutputWorkflowScheme = "did://sbom/cyclonedx"

func SBOMWorkflow(ic workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
	var sbomList []workflow.Data

	var workflowEngineInstance = ic.GetEngine()

	DepGraphWorkflowID, err := url.Parse(DepGraphWorkflowScheme)
	
	if err != nil {
		// TODO: We need to propogate these errors to the core engine.
		return sbomList, err
	}

	depGraphData, err := workflowEngineInstance.Invoke(DepGraphWorkflowID)

	if err != nil {
		// TODO: We need to propogate these errors to the core engine.
		return sbomList, err
	}

	// iterate over depgraphs and generate sbom
	for _, depGraph := range depGraphData {
		identifier := depGraph.GetIdentifier()
		if identifier.Host == "depgraph" {
			depGraphPayload, ok := depGraph.GetPayload().([]byte)
			if !ok {
				// TODO: We need to propogate these errors to the core engine.
				// Content of the error should be updated later to match the error state.
				return sbomList, errors.New("invalid dependency graph for sbom conversion")
			}

			sbom, err := convertDepGraphToSBOM(context.Background(), ic, depGraphPayload, "cyclonedx+json")
			if err != nil {
				// TODO: We need to propogate these errors to the core engine.
				return sbomList, err
			}

			workflowIdentifier, err := url.Parse(OutputWorkflowScheme)
			if err != nil {
				// TODO: We need to propogate these errors to the core engine.
				return sbomList, err
			}

			// create output data
			data := workflow.NewDataFromInput(depGraph, workflowIdentifier, "application/vnd.cyclonedx+json", sbom)
			sbomList = append(sbomList, data)
		}
	}

	return sbomList, nil
}

func convertDepGraphToSBOM(ctx context.Context, ic workflow.InvocationContext, depGraph []byte, format string) (sbom []byte, err error) {
	baseURL := "https://api.snyk.io"
	apiVersion := "2022-03-31~experimental"

	workflowConfiguration := ic.GetConfiguration()

	token := workflowConfiguration.GetString("token")
	orgID := workflowConfiguration.GetString("org")

	url := fmt.Sprintf(
		"%s/hidden/orgs/%s/sbom?version=%s&format=%s",
		baseURL, orgID, apiVersion, url.QueryEscape(format),
	)

	body := bytes.NewBuffer([]byte(fmt.Sprintf(`{"depGraph":%s}`, depGraph)))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	req.Header.Set("Authorization", fmt.Sprintf("token %s", token))
	req.Header.Set("Content-Type", "application/json")
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("could not convert to SBOM (status: %s)", resp.Status)
	}

	if resp.Header.Get("Content-Type") != "application/vnd.cyclonedx+json" {
		return nil, errors.New("received unexpected response format")
	}

	sbom, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return sbom, nil
}

func Init(e workflow.Engine) error {
	WorkflowID, _ := url.Parse(OutputWorkflowScheme)

	flagset := pflag.NewFlagSet("snyk-cli-extension-sbom", pflag.ExitOnError)
	// TODO
	flagset.String("file", "", "usage docs for file option")
	// TODO
	flagset.StringP("format", "f", "text", "usage docs for format option")

	c := workflow.ConfigurationOptionsFromFlagset(flagset)

	if _, err := e.Register(WorkflowID, c, SBOMWorkflow); err != nil {
		return err
	}

	return nil
}
