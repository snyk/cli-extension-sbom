package snykclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/snyk/cli-extension-sbom/internal/errors"
)

const ContentTypeHeader = "Content-Type"
const MIMETypeJSON = "application/json"

func (t *SnykClient) MonitorDeps(
	ctx context.Context,
	errFactory *errors.ErrorFactory,
	scanResult *ScanResult,
) (*MonitorDepsResponse, error) {
	url := fmt.Sprintf("%s/v1/monitor-dependencies", t.apiBaseURL)

	scanResultReq := ScanResultRequest{ScanResult: *scanResult}
	scanResultJSON, err := json.Marshal(scanResultReq)
	if err != nil {
		return nil, errFactory.NewFatalSBOMMonitorError(err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(scanResultJSON))
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
