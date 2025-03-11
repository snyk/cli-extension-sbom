package snykclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

	var depsResp MonitorDependenciesResponse
	err = json.NewDecoder(resp.Body).Decode(&depsResp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON response: %w", err)
	}

	return &depsResp, nil
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
