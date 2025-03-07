package policy_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-sbom/internal/policy"
)

func TestLoadPolicyFile_FromPolicyPath_Valid(t *testing.T) {
	policyBytes := policy.LoadPolicyFile("./testdata/.snyk", "")
	assert.Equal(t, string(policyBytes), "Foo:\n  Bar\n")
}

func TestLoadPolicyFile_FromPolicyPath_Invalid(t *testing.T) {
	policyBytes := policy.LoadPolicyFile("NOT A PATH", "")
	assert.Equal(t, string(policyBytes), "")
}

func TestLoadPolicyFile_FromSbomPath_Valid(t *testing.T) {
	policyBytes := policy.LoadPolicyFile("", "./testdata/cdx.json")
	assert.Equal(t, string(policyBytes), "Foo:\n  Bar\n")
}

func TestLoadPolicyFile_FromSbomPath_Invalid(t *testing.T) {
	policyBytes := policy.LoadPolicyFile("", "NOT A PATH")
	assert.Equal(t, string(policyBytes), "")
}
