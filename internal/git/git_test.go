package git_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-sbom/internal/git"
)

type testGitExec struct {
	cmdOutput string
	cmdErr    error
}

func (g *testGitExec) Exec(cmd string, args ...string) (string, error) {
	return g.cmdOutput, g.cmdErr
}

func Test_GetRemoteOriginUrl(t *testing.T) {
	testCases := []struct {
		name     string
		origin   string
		expected string
		execErr  error
	}{
		{
			name:     "HTTPS",
			origin:   "https://github.com/snyk/cli-extension-sbom",
			expected: "http://github.com/snyk/cli-extension-sbom",
		},
		{
			name:     "HTTP",
			origin:   "http://github.com/snyk/cli-extension-sbom",
			expected: "http://github.com/snyk/cli-extension-sbom",
		},
		{
			name:     "SSH",
			origin:   "ssh://git@github.com:snyk/cli-extension-sbom.git",
			expected: "http://github.com/snyk/cli-extension-sbom.git",
		},
		{
			name:     "SSH - git prefix",
			origin:   "git@github.com:snyk/cli-extension-sbom.git",
			expected: "http://github.com/snyk/cli-extension-sbom.git",
		},
		{
			name:     "No match returns input",
			origin:   "xxx-test",
			expected: "xxx-test",
		},
		{
			name:     "Trims whitespace from command output",
			origin:   "\ngit@github.com:snyk/cli-extension-sbom.git\n\n",
			expected: "http://github.com/snyk/cli-extension-sbom.git",
		},
		{
			name:     "Whitespace-only output is converted to empty string",
			origin:   "\n\t",
			expected: "",
		},
		{
			name:     "Trims whitespace from command output",
			origin:   "\ngit@github.com:snyk/cli-extension-sbom.git\n\n",
			expected: "http://github.com/snyk/cli-extension-sbom.git",
		},
		{
			name:     "Whitespace-only output is converted to empty string",
			origin:   "\n\t",
			expected: "",
		},
		{
			name:     "Ignore error",
			origin:   "",
			expected: "",
			execErr:  errors.New("git exec error"),
		},
		{
			name:     "Ignore error even if origin is returned",
			origin:   "this should be ignored!",
			expected: "",
			execErr:  errors.New("git exec error"),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			g := git.NewGitCmdWithExec(&testGitExec{cmdOutput: testCase.origin, cmdErr: testCase.execErr})
			assert.Equal(t, testCase.expected, g.GetRemoteOriginURL())
		})
	}
}
