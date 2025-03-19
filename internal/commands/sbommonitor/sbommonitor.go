package sbommonitor

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-sbom/internal/errors"
	"github.com/snyk/cli-extension-sbom/internal/flags"
	"github.com/snyk/cli-extension-sbom/internal/policy"
)

var WorkflowID = workflow.NewWorkflowIdentifier("sbom.monitor")
var WorkflowDataID = workflow.NewTypeIdentifier(WorkflowID, "sbom.monitor")

const FeatureFlagSBOMMonitor = "feature_flag_sbom_monitor"

func RegisterWorkflows(e workflow.Engine) error {
	sbomFlagset := flags.GetSBOMMonitorFlagSet()

	c := workflow.ConfigurationOptionsFromFlagset(sbomFlagset)

	if _, err := e.Register(WorkflowID, c, MonitorWorkflow); err != nil {
		return fmt.Errorf("error while registering %s workflow: %w", WorkflowID, err)
	}

	config_utils.AddFeatureFlagToConfig(e, FeatureFlagSBOMMonitor, "sbomMonitorBeta")

	return nil
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
	// TODO: add this to scan results
	_ = config.GetString(flags.FlagTargetName)
	_ = config.GetString(flags.FlagTargetReference)
	errFactory := errors.NewErrorFactory(logger)

	logger.Println("SBOM Monitor workflow start")

	// As this is an experimental feature, we only want to continue if the experimental flag is set
	if !experimental {
		return nil, errFactory.NewMissingExperimentalFlagError()
	}

	// Check if the feature can be used
	if !config.GetBool(FeatureFlagSBOMMonitor) {
		// TODO: use error factory and a nicer message
		return nil, fmt.Errorf("you cannot use this feature")
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

	// TODO: Add the policy to the scanResult body
	_ = policy.LoadPolicyFile(policyPath, filename)

	data := "SBOM Monitor Success!"
	return []workflow.Data{workflowData([]byte(data), "text/plain")}, nil
}

func workflowData(data []byte, contentType string) workflow.Data {
	return workflow.NewData(WorkflowDataID, contentType, data)
}
