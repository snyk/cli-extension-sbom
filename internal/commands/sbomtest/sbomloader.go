package sbomtest

import (
	"encoding/json"
	"os"

	"github.com/snyk/cli-extension-sbom/internal/errors"
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
