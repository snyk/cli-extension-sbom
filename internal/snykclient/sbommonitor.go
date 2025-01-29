package snykclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"time"

	"github.com/snyk/cli-extension-sbom/internal/errors"

	snyk_errors "github.com/snyk/error-catalog-golang-public/snyk_errors"
)

const sbomMonitorAPIVersion = "2024-07-10~beta"

type SBOMMonitor struct {
	SnykClient *SnykClient
	ID         string
}

func (t *SnykClient) CreateSBOMMonitor(
	ctx context.Context,
	sbomJSON []byte,
	targetName string,
	filename string,
	errFactory *errors.ErrorFactory,
) (*SBOMMonitor, error) {
	url := fmt.Sprintf("%s/closed-beta/orgs/%s/sbom_monitors?version=%s", t.apiBaseURL, t.orgID, sbomMonitorAPIVersion)

	_, filename = path.Split(filename)

	requestBody := CreateSBOMMonitorRequestBody{
		Data: CreateSBOMMonitorRequestData{
			Type: "sbom_monitor",
			Attributes: SBOMMonitorCreateAttributes{
				SBOM:       string(sbomJSON),
				TargetName: targetName,
				Filename:   filename,
			},
		},
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return nil, errFactory.NewFatalSBOMMonitorError(err)
	}

	reader := bytes.NewReader(jsonData)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, reader)
	if err != nil {
		return nil, errFactory.NewFatalSBOMMonitorError(err)
	}
	req.Header.Set("Content-Type", "application/vnd.api+json")

	rsp, err := t.client.Do(req)
	if err != nil {
		return nil, errFactory.NewFatalSBOMMonitorError(err)
	}

	var body CreateSBOMMonitorResponseBody
	if err := parseResponse(rsp, http.StatusCreated, &body); err != nil {
		return nil, errFactory.NewFatalSBOMMonitorError(err)
	}

	return &SBOMMonitor{
		SnykClient: t,
		ID:         body.Data.ID,
	}, nil
}

func (t *SBOMMonitor) GetSBOMMonitorStatus(ctx context.Context, errFactory *errors.ErrorFactory) (SBOMMonitorState, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.statusURL(), http.NoBody)
	if err != nil {
		return SBOMMonitorStateErr, err
	}

	resp, err := t.SnykClient.client.Do(req)
	if err != nil {
		return SBOMMonitorStateErr, err
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return SBOMMonitorStateErr, errFactory.NewFatalSBOMTestError(err)
	}

	// Attempt to parse into a JSON:API error document.
	// If we get errors, we can return the first one as an
	// error-catalog error.
	var errDoc errorDocument
	if err := json.Unmarshal(body, &errDoc); err == nil && len(errDoc.Errors) > 0 {
		err := errDoc.Errors[0]
		// The go-application-framework currently limits output to the title of the error. For it to
		// give more context, we augment the title with additional info.
		return SBOMMonitorStateErr, snyk_errors.Error{
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
		return SBOMMonitorStateErr, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var statusDoc GetSBOMMonitorResponseBody
	if err := json.Unmarshal(body, &statusDoc); err != nil {
		return SBOMMonitorStateErr, errFactory.NewFatalSBOMMonitorError(err)
	}

	return statusDoc.Data.Attributes.State, nil
}

func (t *SBOMMonitor) statusURL() string {
	return fmt.Sprintf(
		"%s/closed-beta/orgs/%s/sbom_monitors/%s?version=%s",
		t.SnykClient.apiBaseURL, t.SnykClient.orgID, t.ID, sbomMonitorAPIVersion,
	)
}

func (t *SBOMMonitor) WaitUntilComplete(ctx context.Context, errFactory *errors.ErrorFactory) error {
	return t.WaitUntilCompleteWithBackoff(ctx, DefaultBackoff, errFactory)
}

func (t *SBOMMonitor) WaitUntilCompleteWithBackoff(ctx context.Context, backoff backoffFn, errFactory *errors.ErrorFactory) error {
	// TODO: fine tune timeout
	ctx, cancel := context.WithTimeout(ctx, time.Minute*5)
	defer cancel()

	for {
		status, err := t.GetSBOMMonitorStatus(ctx, errFactory)
		if err != nil {
			return errFactory.NewFatalSBOMMonitorError(err)
		}

		if status == SBOMMonitorStateErr {
			return errFactory.NewFailedToMonitorSBOMError()
		} else if status == SBOMMonitorStateComplete {
			break
		}

		backoff()
	}

	return nil
}
