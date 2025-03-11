package sbommonitor

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-sbom/internal/errors"
	"github.com/snyk/cli-extension-sbom/internal/flags"
	"github.com/snyk/cli-extension-sbom/internal/policy"
	"github.com/snyk/cli-extension-sbom/internal/snykclient"
	view "github.com/snyk/cli-extension-sbom/internal/view/sbommonitor"
)

var WorkflowID = workflow.NewWorkflowIdentifier("sbom.monitor")
var WorkflowDataID = workflow.NewTypeIdentifier(WorkflowID, "sbom.monitor")

func RegisterWorkflows(e workflow.Engine) error {
	sbomFlagset := flags.GetSBOMMonitorFlagSet()

	c := workflow.ConfigurationOptionsFromFlagset(sbomFlagset)

	if _, err := e.Register(WorkflowID, c, MonitorWorkflow); err != nil {
		return fmt.Errorf("error while registering %s workflow: %w", WorkflowID, err)
	}
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
	targetName := config.GetString(flags.FlagTargetName)
	targetRef := config.GetString(flags.FlagTargetReference)
	errFactory := errors.NewErrorFactory(logger)

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

	logger.Println("Target file:", filename)

	fd, err := os.Open(filename)
	if err != nil {
		// TODO: handle error
		panic(err)
	}

	c := snykclient.NewSnykClient(
		ictx.GetNetworkAccess().GetHttpClient(),
		config.GetString(configuration.API_URL),
		orgID)

	scans, err := c.SBOMConvert(context.Background(), errFactory, fd)
	if err != nil {
		// TODO: handle error
		panic(err)
	}

	logger.Println("Successfully converted SBOM")

	plc := policy.LoadPolicyFile(policyPath, filename)
	res := make([]*snykclient.MonitorDependenciesResponse, 0, len(scans))

	for _, s := range scans {
		logger.Printf("Monitoring dep-graph (%s)\n", s.Identity.Type)
		mres, merr := c.MonitorDependencies(context.Background(), errFactory,
			s.WithSnykPolicy(plc).
				WithTargetReference(targetRef).
				WithTargetName(targetName))
		if merr != nil {
			// TODO: handle error
			// TBD: should this fail the entire command?
			// TBD: how to add this to the output?
			logger.Println("Failed to monitor dep-graph", merr)
			continue
		}
		res = append(res, mres)
	}

	var buf bytes.Buffer
	_, err = view.RenderMonitor(&buf, res)
	if err != nil {
		// TODO: handle error
		panic(err)
	}

	return []workflow.Data{workflow.NewData(WorkflowDataID, "text/plain", buf.Bytes())}, nil
}
