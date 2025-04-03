package git

type Git interface {
	GetRemoteOriginURL() string
}

type GitCmd struct{}

func (g *GitCmd) GetRemoteOriginURL() string {
	return ""
}
