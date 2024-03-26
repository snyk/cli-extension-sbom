package sbomtest_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-sbom/internal/commands/sbomtest"
)

func TestIsSupportedSBOMFormat_Success(t *testing.T) {
	testCases := []struct {
		name    string
		content string
	}{
		{
			name:    "Test is cyclonedx json supported",
			content: "CycloneDX/bomFormat",
		},
		{
			name:    "Test is cyclonedx xml supported",
			content: "cyclonedx/xmlns",
		},
		{
			name:    "Test is spdx supported",
			content: `SPDXRef-DOCUMENT/"spdxVersion"`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(tt *testing.T) {
			reader := strings.NewReader(tc.content)

			ok, err := sbomtest.IsSupportedSBOMFormat(reader)

			require.NoError(t, err)
			require.True(t, ok)
		})
	}
}

func TestOpenFile_FileDoesNotExist(t *testing.T) {
	filename := "testdata/this-file-does-not-exist.txt"

	reader, err := sbomtest.OpenFile(filename)

	require.Error(t, err)
	require.Equal(t, "file does not exist", err.Error())
	require.Nil(t, reader)
}

func TestOpenFile_FileIsDirectory(t *testing.T) {
	folder := "testdata"

	reader, err := sbomtest.OpenFile(folder)

	require.Error(t, err)
	require.Equal(t, "file is a directory", err.Error())
	require.Nil(t, reader)
}
