package sbomtest

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-sbom/internal/errors"
	"github.com/snyk/cli-extension-sbom/internal/flags"
	"github.com/snyk/cli-extension-sbom/internal/sbom"
)

var (
	WorkflowID            = workflow.NewWorkflowIdentifier("sbom.test")
	OsFlowsTestWorkflowID = workflow.NewWorkflowIdentifier("test")
)

func RegisterWorkflows(e workflow.Engine) error {
	sbomFlagset := flags.GetSBOMTestFlagSet()

	c := workflow.ConfigurationOptionsFromFlagset(sbomFlagset)

	if _, err := e.Register(WorkflowID, c, TestWorkflow); err != nil {
		return fmt.Errorf("error while registering %s workflow: %w", WorkflowID, err)
	}
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

	orgID := config.GetString(configuration.ORGANIZATION)
	if orgID == "" {
		return nil, errFactory.NewEmptyOrgError()
	}

	if filename == "" {
		return nil, errFactory.NewMissingFilenameFlagError()
	}

	logger.Println("Target SBOM document:", filename)

	if _, err := sbom.ReadSBOMFile(filename, errFactory); err != nil {
		return nil, err
	}

	osFlowsTestConfig := config.Clone()
	osFlowsTestConfig.Set(flags.FlagSBOM, filename)

	return engine.InvokeWithConfig(OsFlowsTestWorkflowID, osFlowsTestConfig)
}
