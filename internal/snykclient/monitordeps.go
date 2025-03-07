package snykclient

import (
	"bytes"
	"context"
	"encoding/json"
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
		return nil, errFactory.NewFatalSBOMMonitorError(err)
	}
	if t.orgID != "" {
		v := url.Values{"org": {t.orgID}}
		u.RawQuery = v.Encode()
	}

	scanResultReq := ScanResultRequest{ScanResult: *scanResult}
	scanResultJSON, err := json.Marshal(scanResultReq)
	if err != nil {
		return nil, errFactory.NewFatalSBOMMonitorError(err)
	}

	req, err := http.NewRequestWithContext(ctx,
		http.MethodPut,
		u.String(),
		bytes.NewReader(scanResultJSON))
	if err != nil {
		return nil, errFactory.NewFatalSBOMMonitorError(err)
	}

	req.Header.Set(ContentTypeHeader, MIMETypeJSON)

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, errFactory.NewFatalSBOMMonitorError(err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errFactory.NewFatalSBOMMonitorError(err)
	}

	var depsResp MonitorDepsResponse
	err = json.Unmarshal(bodyBytes, &depsResp)
	if err != nil {
		return nil, errFactory.NewFatalSBOMMonitorError(err)
	}

	return &depsResp, nil
}
