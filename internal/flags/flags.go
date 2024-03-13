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
	FlagMavenAggregateProject        = "maven-aggregate-project"
	FlagScanUnmanaged                = "scan-unmanaged"
	FlagScanAllUnmanaged             = "scan-all-unmanaged"
	FlagSubProject                   = "sub-project"
	FlagGradleSubProject             = "gradle-sub-project"
	FlagAllSubProjects               = "all-sub-projects"
	FlagConfigurationMatching        = "configuration-matching"
	FlagConfigurationAttributes      = "configuration-attributes"
	FlagInitScript                   = "init-script"
	FlagYarnWorkspaces               = "yarn-workspaces"
	FlagPythonCommand                = "command"
	FlagPythonSkipUnresolved         = "skip-unresolved"
	FlagPythonPackageManager         = "package-manager"
	FlagNPMStrictOutOfSync           = "strict-out-of-sync"
	FlagNugetAssetsProjectName       = "assets-project-name"
	FlagNugetPkgsFolder              = "packages-folder"
	FlagUnmanagedMaxDepth            = "max-depth"
)

func GetSBOMExportFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("snyk-cli-extension-sbom", pflag.ExitOnError)

	flagSet.Bool(FlagExperimental, false, "Deprecated. Will be ignored.")
	flagSet.Bool(FlagUnmanaged, false, "For C/C++ only, scan all files for known open source dependencies and build an SBOM.")
	flagSet.Bool(FlagAllProjects, false, "Auto-detect all projects in the working directory (including Yarn workspaces).")
	flagSet.Bool(FlagYarnWorkspaces, false, "Detect and scan Yarn Workspaces only when a lockfile is in the root.")
	flagSet.String(FlagExclude, "", "Can be used with --all-projects to indicate directory names and file names to exclude. Must be comma separated.")
	flagSet.String(FlagDetectionDepth, "", "Use with --all-projects to indicate how many subdirectories to search. "+
		"DEPTH must be a number, 1 or greater; zero (0) is the current directory.")
	flagSet.BoolP(FlagPruneRepeatedSubDependencies, "p", false, "Prune dependency trees, removing duplicate sub-dependencies.")
	flagSet.String(FlagFile, "", "Specify a package file.")
	flagSet.String(FlagName, "", "Specify a name for the collection of all projects in the working directory.")
	flagSet.String(FlagVersion, "", "Specify a version for the collection of all projects in the working directory.")
	flagSet.StringP(FlagFormat, "f", "", "Specify the SBOM output format. (cyclonedx1.4+json, cyclonedx1.4+xml, spdx2.3+json)")
	flagSet.Bool(FlagDev, false, "Include development-only dependencies. Applicable only for some package managers.")
	flagSet.Bool(FlagMavenAggregateProject, false, "Ensure all modules are resolvable by the Maven reactor.")
	flagSet.Bool(FlagScanUnmanaged, false, "Specify an individual JAR, WAR, or AAR file.")
	flagSet.Bool(FlagScanAllUnmanaged, false, "Auto-detect Maven, JAR, WAR, and AAR files recursively from the current folder.")
	flagSet.String(FlagSubProject, "", "Name of Gradle sub-project to test.")
	flagSet.String(FlagGradleSubProject, "", "Name of Gradle sub-project to test.")
	flagSet.Bool(FlagAllSubProjects, false, "Test all sub-projects in a multi-project build.")
	flagSet.String(FlagNPMStrictOutOfSync, "true", "Prevent testing out-of-sync lockfiles.")
	flagSet.Bool(FlagNugetAssetsProjectName, false,
		"When you are monitoring a .NET project using NuGet PackageReference uses the project name in project.assets.json if found.")
	flagSet.String(FlagNugetPkgsFolder, "", "Specify a custom path to the packages folder when using NuGet.")
	flagSet.String(FlagConfigurationMatching, "", "Resolve dependencies using only configuration(s) that match the specified Java regular expression.")
	flagSet.String(FlagConfigurationAttributes, "", "Select certain values of configuration attributes to install and resolve dependencies.")
	flagSet.String(FlagInitScript, "", "Use for projects that contain a Gradle initialization script.")
	flagSet.String(FlagPythonCommand, "", "Indicate which specific Python commands to use based on the Python version.")
	flagSet.String(FlagPythonSkipUnresolved, "", "Skip Python packages that cannot be found in the environment.")
	flagSet.String(FlagPythonPackageManager, "", `Add --package-manager=pip to your command if the file name is not "requirements.txt".`)
	flagSet.Int(FlagUnmanagedMaxDepth, 0, "Specify the maximum level of archive extraction for unmanaged scanning.")

	return flagSet
}

func GetSBOMTestFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("snyk-cli-extension-sbom-test", pflag.ExitOnError)

	flagSet.Bool(FlagExperimental, false, "Enable experimental sbom test command.")
	flagSet.String(FlagFile, "", "Specify a SBOM file.")

	return flagSet
}
