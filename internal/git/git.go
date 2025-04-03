package git

import (
	"fmt"
	"net/url"
	"os/exec"
	"regexp"
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

var originRegex = regexp.MustCompile(`(.+@)?(.+):(.+$)`)

func (g *gitCmd) GetRemoteOriginURL() string {
	origin, err := g.ce.Exec("git", "remote", "get-url", "origin")
	if err != nil {
		return ""
	}

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

type cmdExec interface {
	Exec(string, ...string) (string, error)
}

type gitExec struct{}

func (g *gitExec) Exec(name string, args ...string) (string, error) {
	output, err := exec.Command(name, args...).Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}
