package sbommonitor

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	internalErrors "github.com/snyk/cli-extension-sbom/internal/errors"
	"github.com/snyk/cli-extension-sbom/internal/flags"
	"github.com/snyk/cli-extension-sbom/internal/sbom"
	"github.com/snyk/cli-extension-sbom/internal/snykclient"
)

var WorkflowID = workflow.NewWorkflowIdentifier("sbom.monitor")

func RegisterWorkflows(e workflow.Engine) error {
	sbomFlagset := flags.GetSBOMMonitorFlagSet()

	c := workflow.ConfigurationOptionsFromFlagset(sbomFlagset)

	if _, err := e.Register(WorkflowID, c, MonitorWorkflow); err != nil {
		return fmt.Errorf("error while registering %s workflow: %w", WorkflowID, err)
	}
	return nil
}

func loadPolicyFile(policyPath, sbomFilePath string) ([]byte, error) {
	policy := []byte("\n")
	var policyFilePath string
	if policyPath != "" {
		policyFilePath = policyPath
	} else {
		policyFilePath = filepath.Join(filepath.Dir(sbomFilePath), ".snyk")
	}

	_, err := os.Stat(policyFilePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return policy, nil
		} else {
			return nil, err
		}
	}

	bts, err := os.ReadFile(policyFilePath)
	if err != nil {
		return nil, err
	}
	policy = bts

	return policy, nil
}

func MonitorWorkflow(
	ictx workflow.InvocationContext,
	_ []workflow.Data,
) ([]workflow.Data, error) {
	config := ictx.GetConfiguration()
	logger := ictx.GetLogger()
	experimental := config.GetBool(flags.FlagExperimental)
	filename := config.GetString(flags.FlagFile)
	policyPath := config.GetString(flags.FlagPolicyPath)
	errFactory := internalErrors.NewErrorFactory(logger)
	ctx := context.Background()

	logger.Println("SBOM Monitor workflow start")

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

	bts, err := sbom.ReadSBOMFile(filename, errFactory)
	if err != nil {
		return nil, err
	}

	client := snykclient.NewSnykClient(
		ictx.GetNetworkAccess().GetHttpClient(),
		config.GetString(configuration.API_URL),
		orgID,
	)

	// TODO: Add the policy to the scanResult body
	_, err = loadPolicyFile(policyPath, filename)
	if err != nil {
		return nil, err
	}

	sbomMonitor, err := client.CreateSBOMMonitor(ctx, bts, "", filename, errFactory)
	if err != nil {
		return nil, err
	}

	logger.Printf("Created SBOM monitor (ID %s)\n", sbomMonitor.ID)

	data := "SBOM Monitor Success!"
	return []workflow.Data{workflowData([]byte(data), "text/plain")}, err
}

func workflowData(data []byte, contentType string) workflow.Data {
	id := workflow.NewTypeIdentifier(WorkflowID, "sbom.monitor")
	return workflow.NewData(id, contentType, data)
}
