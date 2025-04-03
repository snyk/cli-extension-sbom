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
	gitRemoteUrl := "http://example.com/git-url"

	g := git.NewGitCmdWithExec(&testGitExec{cmdOutput: gitRemoteUrl})
	assert.Equal(t, gitRemoteUrl, g.GetRemoteOriginURL())
}
