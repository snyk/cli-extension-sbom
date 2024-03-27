package sbomtest

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

type foundMatch struct {
	first  bool
	second bool
}

type sbomMatchTuple struct {
	first  string
	second string
}

func (t sbomMatchTuple) key() string {
	return t.first + "-" + t.second
}

var supportedSBOMFormatTuples []sbomMatchTuple = []sbomMatchTuple{
	{"CycloneDX", "bomFormat"},
	{"SPDXRef-DOCUMENT", `"spdxVersion"`},
}

func IsSupportedSBOMFormat(inputFile io.Reader) (bool, error) {
	var foundMatches = make(map[string]foundMatch)
	for _, t := range supportedSBOMFormatTuples {
		foundMatches[t.key()] = foundMatch{false, false}
	}

	bufReader := bufio.NewReader(inputFile)

	for {
		line, err := bufReader.ReadString('\n')
		if err != nil && err != io.EOF {
			return false, err
		}

		for _, t := range supportedSBOMFormatTuples {
			foundMatch := foundMatches[t.key()]

			if strings.Contains(line, t.first) {
				foundMatch.first = true
			}

			if strings.Contains(line, t.second) {
				foundMatch.second = true
			}

			if foundMatch.first && foundMatch.second {
				return true, nil
			}

			foundMatches[t.key()] = foundMatch
		}

		if err == io.EOF {
			break
		}
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

func OpenSBOMFile(filename string) (*os.File, error) {
	file, err := OpenFile(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	isValidSBOM, err := IsSupportedSBOMFormat(file)
	if err != nil {
		return nil, err
	}

	if !isValidSBOM {
		return nil, fmt.Errorf("file is not a supported SBOM format")
	}

	return OpenFile(filename)
}
