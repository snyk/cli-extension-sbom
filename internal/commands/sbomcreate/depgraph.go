package sbomcreate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-sbom/internal/constants"
	"github.com/snyk/cli-extension-sbom/internal/errors"
	"github.com/snyk/cli-extension-sbom/internal/flags"
	"github.com/snyk/cli-extension-sbom/internal/service"
	"github.com/snyk/cli-extension-sbom/internal/util"
)

var DepGraphWorkflowID = workflow.NewWorkflowIdentifier("depgraph")

type DepGraphResult struct {
	Name          string
	DepGraphBytes []json.RawMessage
	ScanErrors    []service.ScanError
}

func GetDepGraph(ictx workflow.InvocationContext) (*DepGraphResult, error) {
	engine := ictx.GetEngine()
	config := ictx.GetConfiguration()
	logger := ictx.GetEnhancedLogger()
	errFactory := errors.NewErrorFactory(logger)
	name := config.GetString(flags.FlagName)
	version := config.GetString(flags.FlagVersion)

	depGraphConfig := config.Clone()
	allowIncomplete := config.GetBool(flags.FlagAllowIncompleteSBOM)

	if allowIncomplete {
		depGraphConfig.Set("fail-fast", false)
		depGraphConfig.Set("effective-graph-with-errors", true)
	} else if config.GetBool(flags.FlagAllProjects) {
		depGraphConfig.Set("fail-fast", true)
	}

	// Currently, we don't support dotnet runtime resolution for SBOMs.
	// This will come in a future release.
	depGraphConfig.Set("dotnet-runtime-resolution", false)

	useSCAPlugins, err := shouldUseSCAPlugins(config, logger)
	if err != nil {
		return nil, err
	}
	if useSCAPlugins {
		depGraphConfig.Set("use-sbom-resolution", true)
		depGraphConfig.Set("force-single-graph", true)
	}

	depGraphs, err := engine.InvokeWithConfig(DepGraphWorkflowID, depGraphConfig)
	if err != nil {
		return nil, errFactory.NewDepGraphWorkflowError(err)
	}

	depGraphsBytes := make([]json.RawMessage, 0, len(depGraphs))
	var scanErrors []service.ScanError
	for _, dg := range depGraphs {
		if errList := dg.GetErrorList(); len(errList) > 0 {
			subject := dg.GetContentLocation()
			for i := range errList {
				msg := errList[i].Detail
				if msg == "" {
					msg = errList[i].Title
				}
				scanErrors = append(scanErrors, service.ScanError{Subject: subject, Text: msg})
			}
			continue
		}
		depGraphBytes, err := getPayloadBytes(dg)
		if err != nil {
			return nil, errFactory.NewDepGraphWorkflowError(err)
		}
		depGraphsBytes = append(depGraphsBytes, depGraphBytes)
	}
	numGraphs := len(depGraphsBytes)
	logger.Printf("Generating documents for %d depgraph(s)\n", numGraphs)
	if numGraphs != 1 || len(scanErrors) > 0 {
		if name == "" {
			// Fall back to current working directory
			wd, err := os.Getwd()
			if err != nil {
				return nil, errFactory.IndeterminateWorkingDirectory(err)
			}
			name = filepath.Base(wd)
		}
		logger.Printf("Document subject: { Name: %q, Version: %q }\n", name, version)
	}

	return &DepGraphResult{
		Name:          name,
		DepGraphBytes: depGraphsBytes,
		ScanErrors:    scanErrors,
	}, nil
}

func getInputDirectories(config configuration.Configuration) ([]string, error) {
	inputDirs := config.GetStringSlice(configuration.INPUT_DIRECTORY)
	if len(inputDirs) == 0 {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("failed to determine working directory: %w", err)
		}
		inputDirs = []string{cwd}
	}

	return inputDirs, nil
}

func shouldUseSCAPlugins(config configuration.Configuration, logger *zerolog.Logger) (bool, error) {
	inputDirs, err := getInputDirectories(config)
	if err != nil {
		return false, err
	}

	allProjects := config.GetBool(flags.FlagAllProjects)
	fileFlag := config.GetString(flags.FlagFile)

	// Check if uv support should trigger: first check if uv.lock exists and then check if the FF is enabled.
	uvLockExists := util.HasUvLockFileInAnyDir(inputDirs, fileFlag, allProjects, logger)
	if uvLockExists {
		ffUvCLI := config.GetBool(constants.FeatureFlagUvCLI)
		if ffUvCLI {
			logger.Println("uv support enabled and uv.lock found, using SCA plugin resolution in depgraph workflow")
			return true, nil
		} else {
			logger.Println("uv.lock found but uv feature flag disabled, using standard depgraph workflow")
		}
	} else {
		logger.Println("Invoking depgraph workflow")
	}

	return false, nil
}

func getPayloadBytes(data workflow.Data) ([]byte, error) {
	payload := data.GetPayload()
	bytes, ok := payload.([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid payload type (want []byte, got %T)", payload)
	}
	return bytes, nil
}
