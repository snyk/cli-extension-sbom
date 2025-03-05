package sbommonitor

import (
	"context"
	"fmt"
	"strings"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-sbom/internal/errors"
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

func MonitorWorkflow(
	ictx workflow.InvocationContext,
	_ []workflow.Data,
) ([]workflow.Data, error) {
	config := ictx.GetConfiguration()
	logger := ictx.GetLogger()
	experimental := config.GetBool(flags.FlagExperimental)
	filename := config.GetString(flags.FlagFile)
	errFactory := errors.NewErrorFactory(logger)
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

	scanResults, err := client.ConvertSBOM(ctx, errFactory, bts, filename)
	if err != nil {
		return nil, err
	}

	monitors := make([]snykclient.MonitorDepsResponse, 0)
	for _, sr := range scanResults {
		monitor, err := client.MonitorDeps(ctx, errFactory, &sr)
		if err != nil {
			return nil, err
		}

		monitors = append(monitors, *monitor)
	}

	output := formatMonitorOutput(monitors)
	return []workflow.Data{workflowData([]byte(output), "text/plain")}, nil
}

func formatMonitorOutput(monitors []snykclient.MonitorDepsResponse) string {
	var sb strings.Builder
	for _, m := range monitors {
		if sb.Len() > 0 {
			sb.WriteString("\n")
			sb.WriteString("-------------------------------------------------------")
			sb.WriteString("\n")
		}

		sb.WriteString("\n")
		sb.WriteString("Monitoring '")
		sb.WriteString(m.ProjectName)
		sb.WriteString("'\n\n")
		sb.WriteString("Explore this snapshot at ")
		sb.WriteString(m.URI)
		sb.WriteString("\n\n")
		sb.WriteString("Notifications about newly disclosed issues related to these dependencies will be emailed to you.")
		sb.WriteString("\n\n")
	}

	return sb.String()
}

func workflowData(data []byte, contentType string) workflow.Data {
	id := workflow.NewTypeIdentifier(WorkflowID, "sbom.monitor")
	return workflow.NewData(id, contentType, data)
}
