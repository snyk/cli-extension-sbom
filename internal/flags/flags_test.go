package flags_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	. "github.com/snyk/cli-extension-sbom/internal/flags"
)

func TestGetFlagSet(t *testing.T) {
	flagSet := GetFlagSet()

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
			isBool:   true,
			expected: false,
		},
		{
			flagName: FlagPythonPackageManager,
			isBool:   false,
			expected: "",
		},
		{
			flagName: FlagNPMStrictOutOfSync,
			isBool:   true,
			expected: true,
		},
		{
			flagName: FlagNugetAssetsProjectName,
			isBool:   false,
			expected: "",
		},
		{
			flagName: FlagNugetPkgsFolder,
			isBool:   false,
			expected: "",
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
