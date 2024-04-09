package sbomcreate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/snyk/cli-extension-sbom/internal/flags"

	cli_errors "github.com/snyk/error-catalog-golang/cli"
	"github.com/snyk/error-catalog-golang/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

var DepGraphWorkflowID = workflow.NewWorkflowIdentifier("depgraph")

type DepGraphResult struct {
	Name          string
	DepGraphBytes []json.RawMessage
}

func GetDepGraph(ictx workflow.InvocationContext) (*DepGraphResult, error) {
	engine := ictx.GetEngine()
	config := ictx.GetConfiguration()
	logger := ictx.GetLogger()
	name := config.GetString(flags.FlagName)
	version := config.GetString(flags.FlagVersion)

	logger.Println("Invoking depgraph workflow")

	depGraphConfig := config.Clone()
	if config.GetBool(flags.FlagAllProjects) {
		depGraphConfig.Set("fail-fast", true)
	}
	depGraphs, err := engine.InvokeWithConfig(DepGraphWorkflowID, depGraphConfig)
	if err != nil {
		return nil, cli_errors.NewDepgraphWorkflowError("", snyk_errors.WithCause(err))
	}

	numGraphs := len(depGraphs)
	logger.Printf("Generating documents for %d depgraph(s)\n", numGraphs)
	depGraphsBytes := make([]json.RawMessage, numGraphs)
	for i, depGraph := range depGraphs {
		depGraphBytes, err := getPayloadBytes(depGraph)
		if err != nil {
			return nil, cli_errors.NewDepgraphWorkflowError("", snyk_errors.WithCause(err))
		}
		depGraphsBytes[i] = depGraphBytes
	}
	if numGraphs > 1 {
		if name == "" {
			// Fall back to current working directory
			wd, err := os.Getwd()
			if err != nil {
				return nil, cli_errors.NewIndeterminateWorkingDirectoryError("", snyk_errors.WithCause(err))
			}
			name = filepath.Base(wd)
		}
		logger.Printf("Document subject: { Name: %q, Version: %q }\n", name, version)
	}

	return &DepGraphResult{
		Name:          name,
		DepGraphBytes: depGraphsBytes,
	}, nil
}

func getPayloadBytes(data workflow.Data) ([]byte, error) {
	payload := data.GetPayload()
	bytes, ok := payload.([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid payload type (want []byte, got %T)", payload)
	}
	return bytes, nil
}
