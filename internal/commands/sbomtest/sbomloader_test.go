package sbomtest_test

import (
	"bytes"
	_ "embed"
	"log"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-sbom/internal/commands/sbomtest"
	"github.com/snyk/cli-extension-sbom/internal/errors"
)

//go:embed testdata/bom.json
var sbomJson string

var logger = log.New(&bytes.Buffer{}, "", 0)
var errFactory = errors.NewErrorFactory(logger)

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

	sbomContent, err := sbomtest.ReadSBOMFile(filename, errFactory)

	require.Error(t, err)
	require.Equal(t, "The given filepath \"testdata/this-file-does-not-exist.txt\" does not exist.", err.Error())
	require.Nil(t, sbomContent)
}

func TestReadSBOMFile_FileIsDirectory(t *testing.T) {
	folder := "testdata"

	sbomContent, err := sbomtest.ReadSBOMFile(folder, errFactory)

	require.Error(t, err)
	require.Equal(t, "The path provided points to a directory. Please ensure the `--file` flag value is pointing to a file.", err.Error())
	require.Nil(t, sbomContent)
}

func TestReadSBOMSuccessfully(t *testing.T) {
	sbomContent, err := sbomtest.ReadSBOMFile("testdata/bom.json", errFactory)

	require.NoError(t, err)
	require.Equal(t, sbomJson, string(sbomContent))
}
