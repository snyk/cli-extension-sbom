package cmd_exec

import (
	"fmt"
	"net/url"
	"os/exec"
	"regexp"
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

var originRegex = regexp.MustCompile(`(.+@)?(.+):(.+$)`)

func (g *cliRemoteRepoURLGetter) GetRemoteOriginURL() string {
	origin, err := g.exec.Exec("git", "remote", "get-url", "origin")
	if err != nil {
		return ""
	}

	origin = strings.TrimSpace(origin)
	if origin == "" {
		return ""
	}

	u, err := url.Parse(origin)
	if err == nil && u.Host != "" && u.Scheme != "" && (u.Scheme == "ssh" || u.Scheme == "http" || u.Scheme == "https") {
		return fmt.Sprintf("http://%s%s", u.Host, u.Path)
	} else {
		matches := originRegex.FindStringSubmatch(origin)
		if len(matches) == 4 && matches[2] != "" && matches[3] != "" {
			return fmt.Sprintf("http://%s/%s", matches[2], matches[3])
		} else {
			return origin
		}
	}
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
