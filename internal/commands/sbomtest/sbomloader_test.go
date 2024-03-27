package sbomtest_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-sbom/internal/commands/sbomtest"
)

func TestIsSupportedSBOMFormat_Success(t *testing.T) {
	testCases := []struct {
		name           string
		content        string
		expectedResult bool
	}{
		{
			name:           "Test is cyclonedx json supported",
			content:        "CycloneDX/bomFormat",
			expectedResult: true,
		},
		{
			name:           "Test is cyclonedx xml is not supported",
			content:        "cyclonedx/xmlns",
			expectedResult: false,
		},
		{
			name:           "Test is spdx supported",
			content:        `SPDXRef-DOCUMENT/"spdxVersion"`,
			expectedResult: true,
		},
		{
			name: "Document not supported",
			content: `Lorem ipsum dolor sit amet,
						consectetur adipiscing elit,
						sed do eiusmod tempor incididunt ut labore et dolore magna aliqua`,
			expectedResult: false,
		},
		{
			name:           "Test is not spdx - missing version",
			content:        `SPDXRef-DOCUMENT`,
			expectedResult: false,
		},
		{
			name:           "Test is not spdx - missing document",
			content:        `"spdxVersion"`,
			expectedResult: false,
		},
		{
			name:           "Test is not cyclonedx json - missing format",
			content:        "CycloneDX",
			expectedResult: false,
		},
		{
			name:           "Test is not cyclonedx json - missing document",
			content:        "bomFormat",
			expectedResult: false,
		},
		{
			name: "Test is cyclonedx matches over multiple lines",
			content: `CycloneDX
								asdf
								bomFormat`,
			expectedResult: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(tt *testing.T) {
			reader := strings.NewReader(tc.content)

			ok, err := sbomtest.IsSupportedSBOMFormat(reader)

			require.NoError(t, err)
			require.Equal(t, tc.expectedResult, ok)
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
