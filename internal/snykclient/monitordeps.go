//nolint:goconst // Refusing to declare a constant for a string we use in fmt.Errorf.
package snykclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/snyk/cli-extension-sbom/internal/errors"
)

const ContentTypeHeader = "Content-Type"
const MIMETypeJSON = "application/json"

func (t *SnykClient) MonitorDependencies(
	ctx context.Context,
	errFactory *errors.ErrorFactory,
	scanResult *ScanResult,
) (*MonitorDependenciesResponse, error) {
	u, err := url.Parse(t.apiBaseURL + "/v1/monitor-dependencies")
	if err != nil {
		return nil, fmt.Errorf("failed to generate url: %w", err)
	}
	if t.orgID != "" {
		v := url.Values{"org": {t.orgID}}
		u.RawQuery = v.Encode()
	}

	var reqBody bytes.Buffer
	if err = json.NewEncoder(&reqBody).Encode(ScanResultRequest{ScanResult: *scanResult}); err != nil {
		return nil, fmt.Errorf("failed to encode request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx,
		http.MethodPut,
		u.String(),
		&reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set(ContentTypeHeader, MIMETypeJSON)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Check for an unsuccessful response from the v1 API
	if err = getErrorFromV1Response(resp); err != nil { //nolint:gocritic // ok to reuse err variable.
		return nil, err
	}

	var respBody MonitorDependenciesResponse
	if err = json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &respBody, nil
}

func (r *ScanResult) WithSnykPolicy(plc []byte) *ScanResult {
	if len(plc) > 0 {
		r.Policy = string(plc)
	}
	return r
}

func (r *ScanResult) WithTargetName(n string) *ScanResult {
	if n != "" {
		r.Target.Name = n
	}
	return r
}

func (r *ScanResult) WithTargetReference(ref string) *ScanResult {
	if ref != "" {
		r.TargetReference = ref
	}
	return r
}

// getErrorFromV1Response parses an error response from the v1 API
// and formats it into a human-readable string.
//
// The error responses from the v1 API are not adhering to one
// single schema, but can come in all shapes and sizes, even
// be text/plain.
func getErrorFromV1Response(r *http.Response) error {
	// We are only interested in 4xx and 5xx errors.
	if r.StatusCode < 400 {
		return nil
	}

	type v1APIErr struct {
		// JSON:API Errors schema
		Errors []struct {
			Details string `json:"details"`
		} `json:"errors"`

		// Legacy error schemas
		Message string `json:"message"`
		ErrRef  string `json:"errorRef"`
	}

	// Read entire body so we can fall back if JSON-decoding
	// fails.
	bod, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("unknown error (%s)", r.Status)
	}

	var apiErr v1APIErr
	if err := json.Unmarshal(bod, &apiErr); err == nil {
		// We're dealing with JSON.
		if len(apiErr.Errors) > 0 {
			// JSON:API error object. Use the first item, it's likely the only one.
			return fmt.Errorf("%s (%s)", apiErr.Errors[0].Details, r.Status)
		}

		return fmt.Errorf("%s (%s)", apiErr.Message, r.Status)
	}

	// Not JSON. Use the body as raw text.
	return fmt.Errorf("%s (%s)", bod, r.Status)
}
