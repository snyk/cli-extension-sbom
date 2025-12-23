package sbom_test

import (
	"bytes"
	_ "embed"
	"errors"
	"os"
	"testing"

	"github.com/rs/zerolog"
	snyk_errors "github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/require"

	errs "github.com/snyk/cli-extension-sbom/internal/errors"
	"github.com/snyk/cli-extension-sbom/internal/sbom"
)

//go:embed testdata/bom.json
var sbomJson string

var logger = zerolog.New(&bytes.Buffer{})
var errFactory = errs.NewErrorFactory(&logger)

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

			ok := sbom.IsSBOMJSON(r)

			require.Equal(t, tc.expectedResult, ok)
		})
	}
}

func TestReadSBOMFile_FileDoesNotExist(t *testing.T) {
	filename := "testdata/this-file-does-not-exist.txt"

	sbomContent, err := sbom.ReadSBOMFile(filename, errFactory)

	require.Error(t, err)
	var snykErr snyk_errors.Error
	require.True(t, errors.As(err, &snykErr))
	require.Equal(t, "Invalid flag option", snykErr.Title)
	require.Equal(t, `The given filepath "testdata/this-file-does-not-exist.txt" does not exist.`, snykErr.Detail)
	require.Nil(t, sbomContent)
}

func TestReadSBOMFile_FileIsDirectory(t *testing.T) {
	folder := "testdata"

	sbomContent, err := sbom.ReadSBOMFile(folder, errFactory)

	require.Error(t, err)
	var snykErr snyk_errors.Error
	require.True(t, errors.As(err, &snykErr))
	require.Equal(t, "Invalid flag option", snykErr.Title)
	require.Equal(t, "The path provided points to a directory. Please ensure the `--file` flag value is pointing to a file.", snykErr.Detail)

	require.Nil(t, sbomContent)
}

func TestReadSBOMFile_FileSizeExceedsLimit(t *testing.T) {
	// Create a temporary file that exceeds the size limit
	tmpFile, err := os.CreateTemp("", "large-sbom-*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	// Write data slightly larger than the limit
	data := make([]byte, sbom.FileSizeLimit+1)
	_, err = tmpFile.Write(data)
	require.NoError(t, err)
	require.NoError(t, tmpFile.Close())

	sbomContent, err := sbom.ReadSBOMFile(tmpFile.Name(), errFactory)

	require.Error(t, err)
	var snykErr snyk_errors.Error
	require.True(t, errors.As(err, &snykErr))
	require.Equal(t, "Invalid flag option", snykErr.Title)
	require.Equal(t, "The provided file is too large. The maximum supported file size is 50 MB.", snykErr.Detail)
	require.Nil(t, sbomContent)
}

func TestReadSBOMFile_InvalidFileSuffix(t *testing.T) {
	t.Run("wrong extension", func(t *testing.T) {
		// Create a temporary file with an invalid extension
		tmpFile, err := os.CreateTemp("", "sbom-*.xml")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		// Write valid JSON content but with wrong extension
		_, err = tmpFile.WriteString(`{"foo":"bar"}`)
		require.NoError(t, err)
		require.NoError(t, tmpFile.Close())

		sbomContent, err := sbom.ReadSBOMFile(tmpFile.Name(), errFactory)

		require.Error(t, err)
		var snykErr snyk_errors.Error
		require.True(t, errors.As(err, &snykErr))
		require.Equal(t, "Invalid flag option", snykErr.Title)
		expectedDetail := "The file provided by the `--file` flag has an unsupported extension " +
			`".xml". Please ensure the file has a .json extension.`
		require.Equal(t, expectedDetail, snykErr.Detail)
		require.Nil(t, sbomContent)
	})

	t.Run("no extension", func(t *testing.T) {
		// Create a temporary file without any extension
		tmpFile, err := os.CreateTemp("", "sbom-no-ext")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		// Write valid JSON content but with no extension
		_, err = tmpFile.WriteString(`{"foo":"bar"}`)
		require.NoError(t, err)
		require.NoError(t, tmpFile.Close())

		sbomContent, err := sbom.ReadSBOMFile(tmpFile.Name(), errFactory)

		require.Error(t, err)
		var snykErr snyk_errors.Error
		require.True(t, errors.As(err, &snykErr))
		require.Equal(t, "Invalid flag option", snykErr.Title)
		expectedDetail := "The file provided by the `--file` flag has an unsupported extension " +
			`"". Please ensure the file has a .json extension.`
		require.Equal(t, expectedDetail, snykErr.Detail)
		require.Nil(t, sbomContent)
	})
}

func TestReadSBOMFile_InvalidJSON(t *testing.T) {
	// Create a temporary file with invalid JSON content
	tmpFile, err := os.CreateTemp("", "invalid-json-*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	// Write invalid JSON content
	_, err = tmpFile.WriteString("this is not valid json")
	require.NoError(t, err)
	require.NoError(t, tmpFile.Close())

	sbomContent, err := sbom.ReadSBOMFile(tmpFile.Name(), errFactory)

	require.Error(t, err)
	var snykErr snyk_errors.Error
	require.True(t, errors.As(err, &snykErr))
	require.Equal(t, "Invalid flag option", snykErr.Title)
	require.Equal(t, "The file provided by the `--file` flag is not valid JSON.", snykErr.Detail)
	require.Nil(t, sbomContent)
}

func TestReadSBOMSuccessfully(t *testing.T) {
	sbomContent, err := sbom.ReadSBOMFile("testdata/bom.json", errFactory)

	require.NoError(t, err)
	require.Equal(t, sbomJson, string(sbomContent))
}
