package sbomtest

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// IsSBOMJSON checks that a reader looks like it could be a SBOM JSON file.
// It only looks at the first 64 bytes of the reader. It then Trims the whitespace
// and checks if the first character is a '{'. '[' would not be a valid SBOM JSON file.
// This is a very basic check and avoids having to load the entire file into memory.
func IsSBOMJSON(r io.Reader) bool {
	var buf [64]byte
	n, err := r.Read(buf[:])
	if err != nil && err != io.EOF {
		return false
	}

	str := strings.TrimSpace(string(buf[:n]))

	return strings.HasPrefix(str, "{")
}

func openFile(filename string) (*os.File, error) {
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

func OpenSBOMFile(filename string) (*os.File, error) {
	file, err := openFile(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	isValidSBOM := IsSBOMJSON(file)

	if !isValidSBOM {
		return nil, fmt.Errorf("file is not a supported SBOM format")
	}

	return openFile(filename)
}
