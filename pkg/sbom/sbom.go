package sbom

import (
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-sbom/internal/commands/sbomcreate"
	"github.com/snyk/cli-extension-sbom/internal/commands/sbommonitor"
	"github.com/snyk/cli-extension-sbom/internal/commands/sbomtest"
)

func Init(e workflow.Engine) error {
	// Register the "sbom" command
	if err := sbomcreate.RegisterWorkflows(e); err != nil {
		return err
	}

	// Register the "sbom test" command
	if err := sbomtest.RegisterWorkflows(e); err != nil {
		return err
	}

	// Register the "sbom monitor" command
	if err := sbommonitor.RegisterWorkflows(e); err != nil {
		return err
	}

	return nil
}
