package snykclient_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-sbom/internal/mocks"
	"github.com/snyk/cli-extension-sbom/internal/snykclient"
)

var exampleScanResult = snykclient.ScanResult{
	Name:   "Bob",
	Policy: "",
	Facts: []snykclient.ScanResultFact{
		{Type: "depGraph", Data: struct{}{}},
	},
	Target:          snykclient.ScanResultTarget{Name: "myTarget"},
	Identity:        snykclient.ScanResultIdentity{Type: "npm"},
	TargetReference: "",
}

func Test_MonitorDeps(t *testing.T) {
	response := mocks.NewMockResponse(
		"application/json; charset=utf-8",
		[]byte(`{"ok":true,"uri":"https://example.com/","isMonitored":true,"projectName":"myProject"}`),
		http.StatusOK,
	)

	mockHTTPClient := mocks.NewMockSBOMService(response, func(r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "/v1/monitor-dependencies?org=org1", r.RequestURI)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
	})

	client := snykclient.NewSnykClient(mockHTTPClient.Client(), mockHTTPClient.URL, "org1")
	depsResp, err := client.MonitorDeps(context.Background(), errFactory, &exampleScanResult)

	assert.NoError(t, err)
	assert.Equal(t, "https://example.com/", depsResp.URI)
	assert.Equal(t, "myProject", depsResp.ProjectName)
	assert.True(t, depsResp.IsMonitored)
}
