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

func (t *SnykClient) MonitorDeps(
	ctx context.Context,
	errFactory *errors.ErrorFactory,
	scanResult *ScanResult,
) (*MonitorDepsResponse, error) {
	u, err := url.Parse(t.apiBaseURL + "/v1/monitor-dependencies")
	if err != nil {
		return nil, fmt.Errorf("monitor deps api url invalid: %w", err)
	}
	if t.orgID != "" {
		v := url.Values{"org": {t.orgID}}
		u.RawQuery = v.Encode()
	}

	scanResultReq := ScanResultRequest{ScanResult: *scanResult}
	scanResultJSON, err := json.Marshal(scanResultReq)
	if err != nil {
		return nil, fmt.Errorf("failed to create scan result request JSON: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx,
		http.MethodPut,
		u.String(),
		bytes.NewReader(scanResultJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set(ContentTypeHeader, MIMETypeJSON)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode) //nolint:goconst // ok to repeat error message.
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var depsResp MonitorDepsResponse
	err = json.Unmarshal(bodyBytes, &depsResp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON response: %w", err)
	}

	return &depsResp, nil
}
