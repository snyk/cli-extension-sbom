package cmd_exec

import (
	"os/exec"
	"strings"
)

type RemoteRepoURLGetter interface {
	GetRemoteOriginURL() string
}

type cliRemoteRepoURLGetter struct {
	exec cmdExecutor
}

func NewCliRemoteRepoURLGetter() *cliRemoteRepoURLGetter {
	return NewRemoteRepoURLGetter(&cliCmdExecutor{})
}

func NewRemoteRepoURLGetter(c cmdExecutor) *cliRemoteRepoURLGetter {
	return &cliRemoteRepoURLGetter{exec: c}
}

func (g *cliRemoteRepoURLGetter) GetRemoteOriginURL() string {
	origin, err := g.exec.Exec("git", "remote", "get-url", "origin")
	if err != nil {
		return ""
	}

	return strings.TrimSpace(origin)
}

type cmdExecutor interface {
	Exec(string, ...string) (string, error)
}

type cliCmdExecutor struct{}

func (g *cliCmdExecutor) Exec(name string, args ...string) (string, error) {
	output, err := exec.Command(name, args...).Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}
