package sbomtest

import (
	"encoding/json"
	"os"

	cli_errors "github.com/snyk/error-catalog-golang/cli"
	"github.com/snyk/error-catalog-golang/snyk_errors"
)

func IsSBOMJSON(b []byte) bool {
	var sbom map[string]interface{}
	err := json.Unmarshal(b, &sbom)
	return err == nil
}

func ReadSBOMFile(filename string) ([]byte, error) {
	// Check if file exists
	info, err := os.Stat(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, cli_errors.NewMissingFileError("")
		}
		return nil, cli_errors.NewFailedToReadFileError("", snyk_errors.WithCause(err))
	}

	// Check if it's a directory
	if info.IsDir() {
		return nil, cli_errors.NewFileIsDirError("")
	}

	// Open file and read it
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, cli_errors.NewFailedToReadFileError("", snyk_errors.WithCause(err))
	}

	isValidSBOM := IsSBOMJSON(b)

	if !isValidSBOM {
		return nil, cli_errors.NewUnsupportedSBOMFormatError("")
	}

	return b, nil
}
