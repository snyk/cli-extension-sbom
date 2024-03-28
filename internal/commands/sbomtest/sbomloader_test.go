package sbomtest_test

import (
	_ "embed"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-sbom/internal/commands/sbomtest"
)

//go:embed testdata/bom.json
var sbomJson string

func TestIsSBOMJSON(t *testing.T) {
	testCases := []struct {
		name           string
		content        string
		expectedResult bool
	}{
		{
			name:           "is json",
			content:        `{"foo":"bar"}`,
			expectedResult: true,
		},
		{
			name:           "bom.json",
			content:        sbomJson,
			expectedResult: true,
		},
		{
			name: "is padded json",
			content: `

			{
				"foo": "bar"
			}`,
			expectedResult: true,
		},
		{
			name:           "is array of json",
			content:        `[{"foo":"bar"}]`,
			expectedResult: false,
		},
		{
			name:           "is string",
			content:        `I am a string`,
			expectedResult: false,
		},
		{
			name:           "base64 encoded string",
			content:        `SSBhbSBhIHN0cmluZwo=`,
			expectedResult: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(tt *testing.T) {
			r := strings.NewReader(tc.content)

			ok := sbomtest.IsSBOMJSON(r)

			require.Equal(t, tc.expectedResult, ok)
		})
	}
}

func TestOpenFile_FileDoesNotExist(t *testing.T) {
	filename := "testdata/this-file-does-not-exist.txt"

	reader, err := sbomtest.OpenSBOMFile(filename)

	require.Error(t, err)
	require.Equal(t, "file does not exist", err.Error())
	require.Nil(t, reader)
}

func TestOpenFile_FileIsDirectory(t *testing.T) {
	folder := "testdata"

	reader, err := sbomtest.OpenSBOMFile(folder)

	require.Error(t, err)
	require.Equal(t, "file is a directory", err.Error())
	require.Nil(t, reader)
}
