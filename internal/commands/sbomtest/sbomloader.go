package sbomtest

import (
	"bytes"
	"errors"
	"io"
	"os"
)

func IsSupportedSBOMFormat(inputFile io.Reader) (bool, error) {
	input, err := io.ReadAll(inputFile)
	if err != nil {
		return false, err
	}
	if bytes.Contains(input, []byte("CycloneDX")) && bytes.Contains(input, []byte("bomFormat")) {
		return true, nil
	}

	if bytes.Contains(input, []byte("cyclonedx")) && bytes.Contains(input, []byte("xmlns")) {
		return true, nil
	}

	if bytes.Contains(input, []byte("SPDXRef-DOCUMENT")) && bytes.Contains(input, []byte(`"spdxVersion"`)) {
		return true, nil
	}

	return false, nil
}

func OpenFile(filename string) (*os.File, error) {
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

	// Check if the user has permission to access the file
	file, err := os.Open(filename)
	if err != nil {
		return nil, errors.New("failed to open file: " + err.Error())
	}

	return file, nil
}
