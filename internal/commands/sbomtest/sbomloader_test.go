package sbomtest_test

import (
	_ "embed"
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
			name: "is ndjson",
			content: `{"foo":"bar"},
{"boo":"baz"}`,
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
			r := []byte(tc.content)

			ok := sbomtest.IsSBOMJSON(r)

			require.Equal(t, tc.expectedResult, ok)
		})
	}
}

func TestReadSBOMFile_FileDoesNotExist(t *testing.T) {
	filename := "testdata/this-file-does-not-exist.txt"

	sbomContent, err := sbomtest.ReadSBOMFile(filename)

	require.Error(t, err)
	require.Equal(t, "file does not exist", err.Error())
	require.Nil(t, sbomContent)
}

func TestReadSBOMFile_FileIsDirectory(t *testing.T) {
	folder := "testdata"

	sbomContent, err := sbomtest.ReadSBOMFile(folder)

	require.Error(t, err)
	require.Equal(t, "file is a directory", err.Error())
	require.Nil(t, sbomContent)
}

func TestReadSBOMSuccessfully(t *testing.T) {
	sbomContent, err := sbomtest.ReadSBOMFile("testdata/bom.json")

	require.NoError(t, err)
	require.Equal(t, sbomJson, string(sbomContent))
}
