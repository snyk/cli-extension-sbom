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
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
)

const (
	apiVersion              = "2022-03-31~experimental"
	mimeTypeCycloneDXJSON   = "application/vnd.cyclonedx+json"
	sbomFormatCycloneDXJSON = "cyclonedx+json"
)

var (
	WorkflowID, _         = url.Parse("did://sbom/cyclonedx") // TODO: need to check with Peter S. if this URL scheme is correct.
	DepGraphWorkflowID, _ = url.Parse("flw://depgraph")       // TODO: import from legacy cli workflows
)

func SBOMWorkflow(
	ictx workflow.InvocationContext,
	input []workflow.Data,
) (sbomList []workflow.Data, err error) {
	var workflowEngineInstance = ictx.GetEngine()

	// TODO: show a spinner before we do any work.
	depGraphs, err := workflowEngineInstance.Invoke(DepGraphWorkflowID)
	if err != nil {
		// TODO: We need to propagate these errors to the core engine.
		return sbomList, fmt.Errorf("error while invoking DepGraph workflow: %w", err)
	}

	for _, depGraph := range depGraphs {
		// TODO: check with Peter S. if this condition is good enough.
		if depGraph.GetIdentifier().Host != "depgraph" {
			continue
		}

		depGraphPayload := depGraph.GetPayload()
		depGraphBytes, ok := depGraphPayload.([]byte)
		if !ok {
			// TODO: We need to propagate these errors to the core engine.
			return nil, fmt.Errorf("invalid dep graph type for SBOM conversion (want []byte, got %T)", depGraphPayload)
		}

		sbom, err := convertDepGraphToSBOM(
			context.Background(),
			ictx,
			depGraphBytes,
			sbomFormatCycloneDXJSON,
		)
		if err != nil {
			// TODO: We need to propagate these errors to the core engine.
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
	ctx context.Context, // TODO: should we rather get a context.Context from the invocation context?
	ictx workflow.InvocationContext,
	depGraph []byte,
	format string,
) (sbom []byte, err error) {
	config := ictx.GetConfiguration()

	token := config.GetString("token")
	orgID := config.GetString("org")
	baseURL := config.GetString(configuration.API_URL)

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		fmt.Sprintf(
			"%s/hidden/orgs/%s/sbom?version=%s&format=%s",
			baseURL, orgID, apiVersion, url.QueryEscape(format),
		),
		bytes.NewBuffer([]byte(fmt.Sprintf(`{"depGraph":%s}`, depGraph))),
	)
	if err != nil {
		return nil, fmt.Errorf("error while creating request: %w", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("token %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
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
