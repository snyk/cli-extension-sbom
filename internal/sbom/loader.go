package sbom

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/snyk/cli-extension-sbom/internal/errors"
)

const (
	// FileSizeLimit is the maximum supported file size (50 MB) for the file upload API in bytes.
	FileSizeLimit = 50_000_000
)

func IsSBOMJSON(b []byte) bool {
	var sbom map[string]interface{}
	err := json.Unmarshal(b, &sbom)
	return err == nil
}

func ReadSBOMFile(filename string, errFactory *errors.ErrorFactory) ([]byte, error) {
	// Check if file exists
	info, err := os.Stat(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errFactory.NewInvalidFilePathError(err, filename)
		}
		return nil, errFactory.NewFailedToReadFileError(err)
	}

	// Check if it's a directory
	if info.IsDir() {
		return nil, errFactory.NewFileIsDirectoryError()
	}

	// Check if file has a valid JSON extension
	ext := strings.ToLower(filepath.Ext(filename))
	if ext != ".json" {
		return nil, errFactory.NewInvalidFileSuffixError(ext)
	}

	// Check if file size exceeds limit
	if info.Size() > FileSizeLimit {
		return nil, errFactory.NewFileSizeExceedsLimitError()
	}

	// Open file and read it
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, errFactory.NewFailedToReadFileError(err)
	}

	isValidSBOM := IsSBOMJSON(b)

	if !isValidSBOM {
		return nil, errFactory.NewInvalidJSONError()
	}

	return b, nil
}
