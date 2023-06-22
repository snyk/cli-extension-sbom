package extensions

import (
	"fmt"

	osdepgraph "github.com/snyk/cli-extension-sbom/internal/opensource/depgraph"
	ossbom "github.com/snyk/cli-extension-sbom/internal/opensource/sbom"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

func Init(e workflow.Engine) error {
	if err := osdepgraph.InitWorkflow(e); err != nil {
		return fmt.Errorf("could not initialize container depgraph workflow: %w", err)
	}

	if err := ossbom.InitWorkflow(e); err != nil {
		return fmt.Errorf("could not initialize container sbom workflow: %w", err)
	}
	return nil
}
