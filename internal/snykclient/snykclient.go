package snykclient

import (
	"net/http"
	"time"
)

type (
	SnykClient struct {
		client     *http.Client
		apiBaseURL string
		orgID      string
	}

	backoffFn func()
)

var DefaultBackoff backoffFn = func() {
	// TODO: fine tune backoff
	time.Sleep(time.Millisecond * 500)
}

func NewSnykClient(c *http.Client, apiBaseURL, orgID string) *SnykClient {
	return &SnykClient{
		client:     createNonRedirectingHTTPClient(c),
		apiBaseURL: apiBaseURL,
		orgID:      orgID,
	}
}

func createNonRedirectingHTTPClient(c *http.Client) *http.Client {
	newClient := http.Client{
		Transport: c.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &newClient
}
