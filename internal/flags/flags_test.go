package flags_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	. "github.com/snyk/cli-extension-sbom/internal/flags"
)

func TestGetSBOMExportFlagSet(t *testing.T) {
	flagSet := GetSBOMCreateFlagSet()

	tc := []struct {
		flagName string
		isBool   bool
		expected interface{}
	}{
		{
			flagName: FlagExperimental,
			isBool:   true,
			expected: false,
		},
		{
			flagName: FlagUnmanaged,
			isBool:   true,
			expected: false,
		},
		{
			flagName: FlagAllProjects,
			isBool:   true,
			expected: false,
		},
		{
			flagName: FlagExclude,
			isBool:   false,
			expected: "",
		},
		{
			flagName: FlagDetectionDepth,
			isBool:   false,
			expected: "",
		},
		{
			flagName: FlagPruneRepeatedSubDependencies,
			isBool:   true,
			expected: false,
		},
		{
			flagName: FlagFile,
			isBool:   false,
			expected: "",
		},
		{
			flagName: FlagName,
			isBool:   false,
			expected: "",
		},
		{
			flagName: FlagVersion,
			isBool:   false,
			expected: "",
		},
		{
			flagName: FlagFormat,
			isBool:   false,
			expected: "",
		},
		{
			flagName: FlagYarnWorkspaces,
			isBool:   true,
			expected: false,
		},
		{
			flagName: FlagPythonCommand,
			isBool:   false,
			expected: "",
		},
		{
			flagName: FlagPythonSkipUnresolved,
			isBool:   false,
			expected: "",
		},
		{
			flagName: FlagPythonPackageManager,
			isBool:   false,
			expected: "",
		},
		{
			flagName: FlagNPMStrictOutOfSync,
			isBool:   false,
			expected: "true",
		},
		{
			flagName: FlagNugetAssetsProjectName,
			isBool:   true,
			expected: false,
		},
		{
			flagName: FlagNugetPkgsFolder,
			isBool:   false,
			expected: "",
		},
		{
			flagName: FlagIncludeProvenance,
			isBool:   true,
			expected: false,
		},
		{
			flagName: FlagFailFast,
			isBool:   true,
			expected: true, // Default value is true
		},
	}

	for _, tt := range tc {
		t.Run(tt.flagName, func(t *testing.T) {
			var val interface{}
			var err error

			if tt.isBool {
				val, err = flagSet.GetBool(tt.flagName)
			} else {
				val, err = flagSet.GetString(tt.flagName)
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expected, val)
		})
	}
}

func TestGetSBOMTestFlagSet(t *testing.T) {
	flagSet := GetSBOMTestFlagSet()

	tc := []struct {
		flagName string
		isBool   bool
		isInt    bool
		expected interface{}
	}{
		{
			flagName: FlagExperimental,
			isBool:   true,
			expected: false,
		},
		{
			flagName: FlagFile,
			isBool:   false,
			expected: "",
		},
		{
			flagName: FlagReachability,
			isBool:   true,
			expected: false,
		},
		{
			flagName: FlagReachabilityFilter,
			isBool:   false,
			expected: "",
		},
		{
			flagName: FlagSourceDir,
			isBool:   false,
			expected: "",
		},
		{
			flagName: FlagRiskScoreThreshold,
			isInt:    true,
			expected: -1,
		},
		{
			flagName: FlagSeverityThreshold,
			isBool:   false,
			expected: "",
		},
	}

	for _, tt := range tc {
		t.Run(tt.flagName, func(t *testing.T) {
			var val interface{}
			var err error

			switch {
			case tt.isBool:
				val, err = flagSet.GetBool(tt.flagName)
			case tt.isInt:
				val, err = flagSet.GetInt(tt.flagName)
			default:
				val, err = flagSet.GetString(tt.flagName)
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expected, val)
		})
	}
}
