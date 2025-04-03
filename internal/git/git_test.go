package git_test

import (
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
			name:     "GIT",
			origin:   "git@github.com:snyk/cli-extension-sbom.git",
			expected: "http://github.com/snyk/cli-extension-sbom.git",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			g := git.NewGitCmdWithExec(&testGitExec{cmdOutput: testCase.origin})
			assert.Equal(t, testCase.expected, g.GetRemoteOriginURL())
		})
	}
}
