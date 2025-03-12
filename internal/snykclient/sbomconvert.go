package snykclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/snyk/cli-extension-sbom/internal/errors"
)

const (
	sbomConvertAPIVersion = "2025-03-06~beta"
	MIMETypeOctetStream   = "application/octet-stream"
)

func (t *SnykClient) SBOMConvert(
	ctx context.Context,
	errFactory *errors.ErrorFactory,
	sbom io.Reader,
) ([]*ScanResult, error) {
	u, err := buildSBOMConvertAPIURL(t.apiBaseURL, sbomConvertAPIVersion, t.orgID)
	if err != nil {
		return nil, fmt.Errorf("sbom convert api url invalid: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		u.String(),
		sbom,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set(ContentTypeHeader, MIMETypeOctetStream)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var convertResp SBOMConvertResponse
	err = json.NewDecoder(resp.Body).Decode(&convertResp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON response: %w", err)
	}

	return convertResp.ScanResults, nil
}

func buildSBOMConvertAPIURL(apiBaseURL, apiVersion, orgID string) (*url.URL, error) {
	u, err := url.Parse(apiBaseURL)
	if err != nil {
		return nil, err
	}

	u = u.JoinPath("hidden", "orgs", orgID, "sboms", "convert")

	query := url.Values{"version": {apiVersion}}
	u.RawQuery = query.Encode()

	return u, nil
}
