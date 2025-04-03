package git

import (
	"os/exec"
	"strings"
)

type Git interface {
	GetRemoteOriginURL() string
}

type gitCmd struct {
	ce cmdExec
}

func NewGitCmd() *gitCmd {
	return NewGitCmdWithExec(&gitExec{})
}

func NewGitCmdWithExec(c cmdExec) *gitCmd {
	return &gitCmd{ce: c}
}

func (g *gitCmd) GetRemoteOriginURL() string {
	cmdOutput, err := g.ce.Exec("git", "remote", "get-url", "origin")
	if err != nil {
		return ""
	}
	// Parse cmdOutput
	return ""
}

type cmdExec interface {
	Exec(string, ...string) (string, error)
}

type gitExec struct{}

func (g *gitExec) Exec(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var out strings.Builder
	err := cmd.Run()
	if err != nil {
		return "", err
	}
	return out.String(), nil
}
