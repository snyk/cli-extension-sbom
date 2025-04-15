package sbomtest_test

import (
	"fmt"
	"github.com/rs/zerolog"
	"github.com/snyk/cli-extension-sbom/internal/commands/sbomtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"path/filepath"
	"testing"
)

func Test_ListsSources_Simplest(t *testing.T) {
	mockLogger := zerolog.New(io.Discard)

	sourceDir := filepath.Join("testdata", "sources", "simplest")
	filesCh, err := sbomtest.GetFilesForPath(sourceDir, &mockLogger, 2)
	require.NoError(t, err)

	var files = []string{}
	for file := range filesCh {
		files = append(files, file)
		fmt.Printf("File: %s\n", file)
	}
	assert.Len(t, files, 2, "Expecting 2 files")
	assert.Contains(t, files, filepath.Join(sourceDir, "package.json"))
	assert.Contains(t, files, filepath.Join(sourceDir, "src", "index.js"))
}

func Test_ListsSources_WithIgnores(t *testing.T) {
	mockLogger := zerolog.New(io.Discard)

	sourceDir := filepath.Join("testdata", "sources", "with-ignores")
	filesCh, err := sbomtest.GetFilesForPath(sourceDir, &mockLogger, 2)
	require.NoError(t, err)

	var files = []string{}
	for file := range filesCh {
		files = append(files, file)
		fmt.Printf("File: %s\n", file)
	}
	assert.Len(t, files, 3, "Expecting 3 files")
	assert.Contains(t, files, filepath.Join(sourceDir, ".gitignore"))
	assert.Contains(t, files, filepath.Join(sourceDir, "package.json"))
	assert.Contains(t, files, filepath.Join(sourceDir, "src", "with-ignores.js"))
}
