package policy

import (
	"os"
	"path/filepath"
)

func LoadPolicyFile(policyPath, sbomFilePath string) []byte {
	var policy []byte
	var policyFilePath string
	if policyPath != "" {
		policyFilePath = policyPath
	} else {
		policyFilePath = filepath.Join(filepath.Dir(sbomFilePath), ".snyk")
	}

	policy, err := os.ReadFile(policyFilePath)
	if err != nil {
		return nil
	}

	return policy
}
