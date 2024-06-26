package snykclient

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/snyk/cli-extension-sbom/internal/errors"
)

const sbomTestAPIVersion = "2024-04-22~beta"

type (
	SnykClient struct {
		client     *http.Client
		apiBaseURL string
		orgID      string
	}

	SBOMTest struct {
		SnykClient *SnykClient
		ID         string
	}

	SBOMTestStatus string

	backoffFn func()
)

var DefaultBackoff backoffFn = func() {
	// TODO: fine tune backoff
	time.Sleep(time.Millisecond * 500)
}

const (
	SBOMTestStatusIndeterminate = SBOMTestStatus("indeterminate")
	SBOMTestStatusProcessing    = SBOMTestStatus("processing")
	SBOMTestStatusError         = SBOMTestStatus("error")
	SBOMTestStatusFinished      = SBOMTestStatus("finished")
)

func NewSnykClient(c *http.Client, apiBaseURL, orgID string) *SnykClient {
	return &SnykClient{
		client:     createNonRedirectingHTTPClient(c),
		apiBaseURL: apiBaseURL,
		orgID:      orgID,
	}
}

func (t *SnykClient) CreateSBOMTest(ctx context.Context, sbomJSON []byte, errFactory *errors.ErrorFactory) (*SBOMTest, error) {
	url := fmt.Sprintf("%s/rest/orgs/%s/sbom_tests?version=%s", t.apiBaseURL, t.orgID, sbomTestAPIVersion)

	jsonAPIReader := strings.NewReader(fmt.Sprintf(`{"data":{"type":"sbom_test","attributes":{"sbom":%s}}}`, sbomJSON))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, jsonAPIReader)
	if err != nil {
		return nil, errFactory.NewFatalSBOMTestError(err)
	}
	req.Header.Set("Content-Type", "application/vnd.api+json")

	rsp, err := t.client.Do(req)
	if err != nil {
		return nil, errFactory.NewFatalSBOMTestError(err)
	}

	var body SBOMTestResourceDocument
	if err := parseResponse(rsp, http.StatusCreated, &body); err != nil {
		return nil, errFactory.NewFatalSBOMTestError(err)
	}

	return &SBOMTest{
		SnykClient: t,
		ID:         body.Data.ID,
	}, nil
}

func (t *SBOMTest) GetResult(ctx context.Context, errFactory *errors.ErrorFactory) (*SBOMTestResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.resultsURL(), http.NoBody)
	if err != nil {
		return nil, errFactory.NewFatalSBOMTestError(err)
	}

	resp, err := t.SnykClient.client.Do(req)
	if err != nil {
		return nil, errFactory.NewFatalSBOMTestError(err)
	}

	var body SBOMTestResultResourceDocument
	if err := parseResponse(resp, http.StatusOK, &body); err != nil {
		return nil, errFactory.NewFatalSBOMTestError(err)
	}

	return body.AsResult(), nil
}

func (t *SBOMTest) GetStatus(ctx context.Context, errFactory *errors.ErrorFactory) (SBOMTestStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.statusURL(), http.NoBody)
	if err != nil {
		return SBOMTestStatusIndeterminate, err
	}

	resp, err := t.SnykClient.client.Do(req)
	if err != nil {
		return SBOMTestStatusIndeterminate, err
	}

	defer resp.Body.Close()

	if resp.StatusCode == http.StatusSeeOther {
		return SBOMTestStatusFinished, nil
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return SBOMTestStatusIndeterminate, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var body SBOMTestStatusResourceDocument
	if err := parseResponse(resp, http.StatusOK, &body); err != nil {
		return SBOMTestStatusIndeterminate, errFactory.NewFatalSBOMTestError(err)
	}
	if body.Data.Attributes.Status == "error" {
		return SBOMTestStatusError, nil
	}

	return SBOMTestStatusProcessing, nil
}

func (t *SBOMTest) WaitUntilComplete(ctx context.Context, errFactory *errors.ErrorFactory) error {
	return t.WaitUntilCompleteWithBackoff(ctx, DefaultBackoff, errFactory)
}

func (t *SBOMTest) WaitUntilCompleteWithBackoff(ctx context.Context, backoff backoffFn, errFactory *errors.ErrorFactory) error {
	// TODO: fine tune timeout
	ctx, cancel := context.WithTimeout(ctx, time.Minute*5)
	defer cancel()

	for {
		status, err := t.GetStatus(ctx, errFactory)
		if err != nil {
			return errFactory.NewFatalSBOMTestError(err)
		}

		if status == SBOMTestStatusError {
			return errFactory.NewFailedToTestSBOMError()
		} else if status == SBOMTestStatusFinished {
			break
		}

		backoff()
	}

	return nil
}

func (t *SBOMTest) statusURL() string {
	return t.buildURL(fmt.Sprintf("/%s", t.ID))
}

func (t *SBOMTest) resultsURL() string {
	return t.buildURL(fmt.Sprintf("/%s/results", t.ID))
}

func (t *SBOMTest) buildURL(pathSuffix string) string {
	return fmt.Sprintf(
		"%s/rest/orgs/%s/sbom_tests%s?version=%s",
		t.SnykClient.apiBaseURL, t.SnykClient.orgID, pathSuffix, sbomTestAPIVersion,
	)
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
