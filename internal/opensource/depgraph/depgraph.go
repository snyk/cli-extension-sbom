package depgraph

import (
	"github.com/snyk/cli-extension-sbom/pkg/depgraph"
	"github.com/snyk/cli-extension-sbom/pkg/flag"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

var Workflow = depgraph.NewWorkflow("opensource depgraph", &OpenSourceConfig{
	AllProjects: flag.Flag[bool]{
		Name:         "all-projects",
		Usage:        "Auto-detect all projects in the working directory (including Yarn workspaces).",
		DefaultValue: false,
	},
	FailFast: flag.Flag[bool]{
		Name:         "fail-fast",
		Usage:        "Fail fast when scanning all projects",
		DefaultValue: false,
	},
	Exclude: flag.Flag[string]{
		Name:         "exclude",
		Usage:        "Can be used with --all-projects to indicate directory Names and file Names to exclude. Must be comma separated.",
		DefaultValue: "",
	},
	DetectionDepth: flag.Flag[string]{
		Name: "detection-depth",
		Usage: "Use with --all-projects to indicate how many subdirectories to search. " +
			"DEPTH must be a number, 1 or greater; zero (0) is the current directory.",
		DefaultValue: "",
	},
	Dev: flag.Flag[bool]{
		Name:         "dev",
		Usage:        "Include dev dependencies",
		DefaultValue: false,
	},
	PruneRepeatedSubdependencies: flag.Flag[bool]{
		Name:         "prune-repeated-subdependencies",
		Shorthand:    "p",
		DefaultValue: false,
		Usage:        "Prune dependency trees, removing duplicate sub-dependencies.",
	},
	Unmanaged: flag.Flag[bool]{
		Name:         "unmanaged",
		Usage:        "For C/C++ only, scan all files for known open source dependencies and build an SBOM.",
		DefaultValue: false,
	},
	// file is only relevant for OS, in container the `Dockerfile` could be specified, but
	// doesn't really influence the results (only the advice).
	File: flag.Flag[string]{
		Name:         "file",
		Usage:        "Specify a package file.",
		DefaultValue: "",
	},
})

func InitWorkflow(e workflow.Engine) error {
	return depgraph.InitWorkflow(e, Workflow)
}

// OpenSourceConfig is the depgraph configuration for OpenSource scans.
type OpenSourceConfig struct {
	AllProjects                  flag.Flag[bool]
	DetectionDepth               flag.Flag[string]
	Exclude                      flag.Flag[string]
	FailFast                     flag.Flag[bool]
	Dev                          flag.Flag[bool]
	File                         flag.Flag[string]
	PruneRepeatedSubdependencies flag.Flag[bool]
	Unmanaged                    flag.Flag[bool]
}

func (o *OpenSourceConfig) Flags() flag.Flags {
	return flag.Flags{
		o.AllProjects,
		o.DetectionDepth,
		o.Exclude,
		o.FailFast,
		o.Dev,
		o.File,
		o.PruneRepeatedSubdependencies,
		o.Unmanaged,
	}
}

func (*OpenSourceConfig) Command() []string {
	return []string{"test", "--print-graph", "--json"}
}
