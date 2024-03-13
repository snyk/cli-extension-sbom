package sbomtest

import "github.com/spf13/pflag"

const (
	SBOMFlagExperimental = "experimental"
	SBOMFlagFile         = "file"
)

func GetSBOMFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("snyk-cli-extension-sbom-test", pflag.ExitOnError)

	flagSet.Bool(SBOMFlagExperimental, false, "Enable experimental sbom test command.")
	flagSet.String(SBOMFlagFile, "", "Specify a SBOM file.")

	return flagSet
}
