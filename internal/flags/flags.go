package flags

import "github.com/spf13/pflag"

const (
	FlagExperimental                 = "experimental"
	FlagUnmanaged                    = "unmanaged"
	FlagFile                         = "file"
	FlagFormat                       = "format"
	FlagAllProjects                  = "all-projects"
	FlagDetectionDepth               = "detection-depth"
	FlagPruneRepeatedSubDependencies = "prune-repeated-subdependencies"
	FlagExclude                      = "exclude"
	FlagName                         = "name"
	FlagVersion                      = "version"
	FlagDev                          = "dev"
)

func GetFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("snyk-cli-extension-sbom", pflag.ExitOnError)

	flagSet.Bool(FlagExperimental, false, "Deprecated. Will be ignored.")
	flagSet.Bool(FlagUnmanaged, false, "For C/C++ only, scan all files for known open source dependencies and build an SBOM.")
	flagSet.Bool(FlagAllProjects, false, "Auto-detect all projects in the working directory (including Yarn workspaces).")
	flagSet.String(FlagExclude, "", "Can be used with --all-projects to indicate directory names and file names to exclude. Must be comma separated.")
	flagSet.String(FlagDetectionDepth, "", "Use with --all-projects to indicate how many subdirectories to search. "+
		"DEPTH must be a number, 1 or greater; zero (0) is the current directory.")
	flagSet.BoolP(FlagPruneRepeatedSubDependencies, "p", false, "Prune dependency trees, removing duplicate sub-dependencies.")
	flagSet.String(FlagFile, "", "Specify a package file.")
	flagSet.String(FlagName, "", "Specify a name for the collection of all projects in the working directory.")
	flagSet.String(FlagVersion, "", "Specify a version for the collection of all projects in the working directory.")
	flagSet.StringP(FlagFormat, "f", "", "Specify the SBOM output format. (cyclonedx1.4+json, cyclonedx1.4+xml, spdx2.3+json)")
	flagSet.Bool(FlagDev, false, "Include development-only dependencies. Applicable only for some package managers.")

	return flagSet
}
