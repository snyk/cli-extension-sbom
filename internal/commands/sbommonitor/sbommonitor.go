package sbommonitor

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-sbom/internal/cmd_exec"
	"github.com/snyk/cli-extension-sbom/internal/errors"
	"github.com/snyk/cli-extension-sbom/internal/flags"
	"github.com/snyk/cli-extension-sbom/internal/policy"
	"github.com/snyk/cli-extension-sbom/internal/snykclient"
	view "github.com/snyk/cli-extension-sbom/internal/view/sbommonitor"
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
	d []workflow.Data,
) ([]workflow.Data, error) {
	return MonitorWorkflowWithDI(ictx, d, cmd_exec.NewCliRemoteRepoURLGetter())
}

func MonitorWorkflowWithDI(
	ictx workflow.InvocationContext,
	_ []workflow.Data,
	remoteRepoUrlGetter cmd_exec.RemoteRepoURLGetter,
) ([]workflow.Data, error) {
	config := ictx.GetConfiguration()
	logger := ictx.GetEnhancedLogger()
	experimental := config.GetBool(flags.FlagExperimental)
	filename := config.GetString(flags.FlagFile)
	policyPath := config.GetString(flags.FlagPolicyPath)
	remoteRepoURL := config.GetString(flags.FlagRemoteRepoURL)
	targetRef := config.GetString(flags.FlagTargetReference)
	errFactory := errors.NewErrorFactory(logger)

	logger.Println("SBOM Monitor workflow start")

	// As this is an experimental feature, we only want to continue if the experimental flag is set
	if !experimental {
		return nil, errFactory.NewMissingExperimentalFlagError()
	}

	// Check if the feature can be used
	if !config.GetBool(FeatureFlagSBOMMonitor) {
		return nil, errFactory.NewFeatureNotPermittedError(FeatureFlagSBOMMonitor)
	}

	logger.Println("Getting preferred organization ID")

	orgID := config.GetString(configuration.ORGANIZATION)
	if orgID == "" {
		return nil, errFactory.NewEmptyOrgError()
	}

	if remoteRepoURL == "" {
		remoteRepoURL = remoteRepoUrlGetter.GetRemoteOriginURL()
	}

	if filename == "" {
		return nil, errFactory.NewMissingFilenameFlagError()
	}

	logger.Println("Target file:", filename)

	if remoteRepoURL == "" {
		return nil, errFactory.NewMissingRemoteRepoUrlError()
	}

	logger.Println("Remote repo URL:", remoteRepoURL)

	fd, err := os.Open(filename)
	if err != nil {
		return nil, errFactory.NewFailedToOpenFileError(err)
	}
	defer fd.Close()

	c := snykclient.NewSnykClient(
		ictx.GetNetworkAccess().GetHttpClient(),
		config.GetString(configuration.API_URL),
		orgID)

	scans, warnings, err := c.SBOMConvert(context.Background(), errFactory, fd, remoteRepoURL)
	if err != nil {
		// Snyk Client returns err from error factory
		return nil, err
	}

	logger.Println("Successfully converted SBOM")

	if len(scans) < 1 {
		return nil, errFactory.NewNoSupportedProjectsError(concatConversionWarnings(warnings))
	}

	plc := policy.LoadPolicyFile(policyPath, filename)

	var buf bytes.Buffer
	r := view.NewRenderer(&buf)

	if err := r.RenderWarnings(warnings); err != nil {
		return nil, errFactory.NewRenderError(err)
	}

	for _, s := range scans {
		logger.Printf("Monitoring dep-graph (%s)\n", s.Identity.Type)

		mres, merr := c.MonitorDependencies(context.Background(), errFactory,
			s.WithSnykPolicy(plc).
				WithTargetReference(targetRef).
				WithTargetRemoteURL(remoteRepoURL))
		if merr != nil {
			logger.Println("Failed to monitor dep-graph", merr)
		}

		if err := r.RenderMonitor(mres, merr); err != nil {
			return nil, errFactory.NewRenderError(err)
		}
	}

	return []workflow.Data{workflow.NewData(WorkflowDataID, "text/plain", buf.Bytes())}, nil
}
