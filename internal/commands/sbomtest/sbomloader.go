package sbomtest

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
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
			return nil, errors.New("file does not exist")
		}
		return nil, errors.New("failed to get file info")
	}

	// Check if it's a directory
	if info.IsDir() {
		return nil, errors.New("file is a directory")
	}

	// Open file and read it
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, errors.New("failed to open file: " + err.Error())
	}

	isValidSBOM := IsSBOMJSON(b)

	if !isValidSBOM {
		return nil, fmt.Errorf("file is not a supported SBOM format")
	}

	return b, nil
}
