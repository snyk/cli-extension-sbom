package snykclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	snyk_errors "github.com/snyk/error-catalog-golang-public/snyk_errors"

	"github.com/snyk/cli-extension-sbom/internal/errors"
)

const sbomTestAPIVersion = "2024-07-10~beta"

type (
	SBOMTest struct {
		SnykClient *SnykClient
		ID         string
	}

	SBOMTestStatus string
)

const (
	SBOMTestStatusIndeterminate = SBOMTestStatus("indeterminate")
	SBOMTestStatusProcessing    = SBOMTestStatus("processing")
	SBOMTestStatusError         = SBOMTestStatus("error") //nolint:goconst // repeated error ok.
	SBOMTestStatusFinished      = SBOMTestStatus("finished")
)

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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return SBOMTestStatusIndeterminate, errFactory.NewFatalSBOMTestError(err)
	}

	// Attempt to parse into a JSON:API error document.
	// If we get errors, we can return the first one as an
	// error-catalog error.
	var errDoc errorDocument
	if err := json.Unmarshal(body, &errDoc); err == nil && len(errDoc.Errors) > 0 {
		err := errDoc.Errors[0]
		// The go-application-framework currently limits output to the title of the error. For it to
		// give more context, we augment the title with additional info.
		return SBOMTestStatusError, snyk_errors.Error{
			StatusCode: resp.StatusCode,
			Detail:     err.Detail,
			ID:         err.ID,
			ErrorCode:  err.Code,
			Title: fmt.Sprintf(
				"%s (Snyk Error Code: %s, SBOM Test ID: %s, Snyk Request ID: %s)",
				err.Title, err.Code, t.ID, resp.Header.Get("Snyk-Request-Id")),
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return SBOMTestStatusIndeterminate, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var statusDoc SBOMTestStatusResourceDocument
	if err := json.Unmarshal(body, &statusDoc); err != nil {
		return SBOMTestStatusIndeterminate, errFactory.NewFatalSBOMTestError(err)
	}
	if statusDoc.Data.Attributes.Status == "error" {
		return SBOMTestStatusError, nil
	}

	return SBOMTestStatusProcessing, nil
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
