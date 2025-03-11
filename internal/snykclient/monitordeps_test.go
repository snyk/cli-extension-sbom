package snykclient_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-sbom/internal/mocks"
	"github.com/snyk/cli-extension-sbom/internal/snykclient"
)

var exampleScanResult = snykclient.ScanResult{
	Name:   "Bob",
	Policy: "",
	Facts: []*snykclient.ScanResultFact{
		{Type: "depGraph", Data: struct{}{}},
	},
	Target:          snykclient.ScanResultTarget{Name: "myTarget"},
	Identity:        snykclient.ScanResultIdentity{Type: "npm"},
	TargetReference: "",
}

func Test_MonitorDependencies(t *testing.T) {
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
	depsResp, err := client.MonitorDependencies(context.Background(), errFactory, &exampleScanResult)

	assert.NoError(t, err)
	assert.Equal(t, "https://example.com/", depsResp.URI)
	assert.Equal(t, "myProject", depsResp.ProjectName)
	assert.True(t, depsResp.IsMonitored)
}

func Test_MonitorDeps_ServerErrors(t *testing.T) {
	testCases := []struct {
		name         string
		statusCode   int
		responseBody string
	}{
		{
			name:         "Forbidden (403) - Feature not available",
			statusCode:   http.StatusForbidden,
			responseBody: `{"message":"This functionality is not available on your plan."}`,
		},
		{
			name:         "Bad Request (400) - Malformed Request",
			statusCode:   http.StatusBadRequest,
			responseBody: "",
		},
		{
			name:         "Internal Server Error (500) - Server Issue",
			statusCode:   http.StatusInternalServerError,
			responseBody: `{"message":"Internal server error."}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			response := mocks.NewMockResponse(
				"application/json; charset=utf-8",
				[]byte(tc.responseBody),
				tc.statusCode,
			)

			mockHTTPClient := mocks.NewMockSBOMService(response)

			client := snykclient.NewSnykClient(mockHTTPClient.Client(), mockHTTPClient.URL, "org1")
			_, err := client.MonitorDependencies(context.Background(), errFactory, &exampleScanResult)

			assert.ErrorContainsf(
				t,
				err,
				fmt.Sprintf("%d", tc.statusCode),
				"Expected error to contain status code %d", tc.statusCode,
			)
		})
	}
}

func TestScanResult_WithSnykPolicy(t *testing.T) {
	r := snykclient.ScanResult{}

	r.WithSnykPolicy([]byte("ignore: {}\n"))

	assert.Equal(t, "ignore: {}\n", r.Policy)
}

func TestScanResult_WithTargetName(t *testing.T) {
	r := snykclient.ScanResult{}

	r.WithTargetName("my-sbom-target")

	assert.Equal(t, "my-sbom-target", r.Target.Name)
}

func TestScanResult_WithTargetReference(t *testing.T) {
	r := snykclient.ScanResult{}

	r.WithTargetReference("main")

	assert.Equal(t, "main", r.TargetReference)
}
