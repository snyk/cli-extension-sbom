package sbom

import (
	"fmt"
	"os"
	"path/filepath"

	osdepgraph "github.com/snyk/cli-extension-sbom/internal/opensource/depgraph"
	"github.com/snyk/cli-extension-sbom/pkg/depgraph"
	"github.com/snyk/cli-extension-sbom/pkg/flag"
	"github.com/snyk/cli-extension-sbom/pkg/sbom"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

var Workflow = sbom.NewWorkflow("sbom", depGraph())

func depGraph() *openSourceDepGraph {
	return &openSourceDepGraph{
		Workflow: osdepgraph.Workflow,
		projectName: flag.Flag[string]{
			Name:         "name",
			Usage:        "Specify a name for the collection of all projects in the working directory.",
			DefaultValue: "",
		},
		version: flag.Flag[string]{
			Name:         "version",
			Usage:        "Specify a version for the collection of all projects in the working directory.",
			DefaultValue: "",
		},
		experimental: flag.Flag[bool]{
			Name:         "experimental",
			Usage:        "Deprecated. Will be ignored",
			DefaultValue: false,
		},
	}
}

func InitWorkflow(e workflow.Engine) error {
	return sbom.InitWorkflow(e, Workflow)
}

type openSourceDepGraph struct {
	*depgraph.Workflow[*osdepgraph.OpenSourceConfig]

	projectName  flag.Flag[string]
	version      flag.Flag[string]
	experimental flag.Flag[bool]
}

func (o *openSourceDepGraph) Flags() flag.Flags {
	return append(o.Workflow.Flags(),
		o.projectName,
		o.version,
		// experimental is ignored
	)
}

func (o *openSourceDepGraph) Invoke(engine workflow.Engine, from configuration.Configuration) ([]workflow.Data, error) {
	dgC := from.Clone()
	if o.SubCommand.AllProjects.Value(from) {
		dgC.Set(o.SubCommand.FailFast.Name, true)
	}

	return engine.InvokeWithConfig(
		o.Identifier(),
		dgC,
	)
}
func (o *openSourceDepGraph) Metadata(c configuration.Configuration, dgs []workflow.Data) (name, version string, err error) {
	// projectName is only relevant if there's multiple depGraphs. If there's only one, it's never
	// needed so it's allowed to be empty.
	if len(dgs) == 1 {
		return "", "", nil
	}

	version = o.version.Value(c)
	if name = o.projectName.Value(c); name != "" {
		return name, version, nil
	}

	// Fall back to current working directory
	wd, err := os.Getwd()
	if err != nil {
		return "", "", fmt.Errorf("error determining working directory: %w", err)
	}

	return filepath.Base(wd), version, nil
}
