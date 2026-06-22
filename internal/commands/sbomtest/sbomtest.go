package sbomtest

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-sbom/internal/errors"
	"github.com/snyk/cli-extension-sbom/internal/flags"
	"github.com/snyk/cli-extension-sbom/internal/sbom"
)

var (
	WorkflowID            = workflow.NewWorkflowIdentifier("sbom.test")
	OsFlowsTestWorkflowID = workflow.NewWorkflowIdentifier("test")
)

// FeatureFlagDflySbomMonitor gates the `sbom test --report` flow (the
// successor to `sbom monitor`) behind the same rollout flag that previously
// gated `sbom monitor`.
const FeatureFlagDflySbomMonitor = "internal_snyk_cli_rollout_dfly_sbom_monitor"

func RegisterWorkflows(e workflow.Engine) error {
	sbomFlagset := flags.GetSBOMTestFlagSet()

	c := workflow.ConfigurationOptionsFromFlagset(sbomFlagset)

	if _, err := e.Register(WorkflowID, c, TestWorkflow); err != nil {
		return fmt.Errorf("error while registering %s workflow: %w", WorkflowID, err)
	}

	config_utils.AddFeatureFlagsToConfig(e, map[string]string{
		FeatureFlagDflySbomMonitor: "rollout-dfly-sbom-monitor",
	})

	return nil
}

func TestWorkflow(
	ictx workflow.InvocationContext,
	_ []workflow.Data,
) ([]workflow.Data, error) {
	config := ictx.GetConfiguration()
	logger := ictx.GetEnhancedLogger()
	engine := ictx.GetEngine()
	filename := config.GetString(flags.FlagFile)
	errFactory := errors.NewErrorFactory(logger)

	logger.Println("SBOM Test workflow start")
	_, err := config.GetStringWithError(configuration.ORGANIZATION)
	if err != nil {
		return nil, err
	}

	if filename == "" {
		return nil, errFactory.NewMissingFilenameFlagError()
	}

	logger.Println("Target SBOM document:", filename)

	if _, err := sbom.ReadSBOMFile(filename, errFactory); err != nil {
		return nil, err
	}

	// `--report` is the successor to the (removed) `sbom monitor` command;
	// keep it behind the same rollout FF so that we don't widen access
	// during the migration.
	if config.GetBool(flags.FlagReport) && !config.GetBool(FeatureFlagDflySbomMonitor) {
		return nil, errFactory.NewFeatureNotPermittedError(FeatureFlagDflySbomMonitor)
	}

	osFlowsTestConfig := config.Clone()
	osFlowsTestConfig.Set(flags.FlagSBOM, filename)

	return engine.InvokeWithConfig(OsFlowsTestWorkflowID, osFlowsTestConfig)
}
