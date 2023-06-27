package flag_test

import (
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-sbom/pkg/flag"
)

func TestFlagWithNonZeroDefaultValue(t *testing.T) {
	f := flag.Flag[string]{
		Name:         "hello",
		Shorthand:    "h",
		Usage:        "say hello",
		DefaultValue: "hi!",
	}

	config := configuration.New()

	arg, ok := f.AsArgument(config)
	require.True(t, ok)
	require.Equal(t, "--hello=hi!", arg)
	// if the DefaultValue is not the zero-value for a type, we expect that to be returned.
	require.Equal(t, "hi!", f.Value(config))

	config.Set(f.Name, "hallo!")
	require.Equal(t, f.Value(config), "hallo!")
	arg, ok = f.AsArgument(config)
	require.True(t, ok)
	require.Equal(t, arg, "--hello=hallo!")
}

func TestFlagWithZeroValue(t *testing.T) {
	f := flag.Flag[string]{
		Name:         "hello",
		Usage:        "say hello",
		DefaultValue: "",
	}
	config := configuration.New()
	_, ok := f.AsArgument(config)
	require.False(t, ok)

	require.Equal(t, "", f.Value(config))

	config.Set(f.Name, "hallo!")
	require.Equal(t, f.Value(config), "hallo!")
	arg, ok := f.AsArgument(config)
	require.True(t, ok)
	require.Equal(t, arg, "--hello=hallo!")

	require.Equal(t, f.Value(config), "hallo!")
}
