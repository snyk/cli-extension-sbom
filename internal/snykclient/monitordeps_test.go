package snykclient_test

import (
	"context"
	"net/http"
	"strconv"
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
	tc := map[string]struct {
		statusCode   int
		responseBody string
		expectedErr  string
	}{
		"400 Bad Request - Plain text response": {
			statusCode:   http.StatusBadRequest,
			responseBody: "Bad Request",
			expectedErr:  "Bad Request (400 Bad Request)",
		},
		"400 Bad Request - JSON response": {
			statusCode:   http.StatusBadRequest,
			responseBody: ` {"message":"Unexpected end of JSON input","errorRef":"5a545f44-7c47-4ccc-a91f-bd6a8bc55079"}`,
			expectedErr:  "Unexpected end of JSON input (400 Bad Request)",
		},
		"401 Unauthorized": {
			statusCode:   http.StatusUnauthorized,
			responseBody: `{"jsonapi":{"version":"1.0"},"errors":[{"status":"401","details":"Unauthorized"}]}`,
			expectedErr:  "Unauthorized (401 Unauthorized)",
		},
		"403 Forbidden": {
			statusCode:   http.StatusForbidden,
			responseBody: `{"message":"This functionality is not available on your plan."}`,
			expectedErr:  "This functionality is not available on your plan. (403 Forbidden)",
		},
		"404 Not Found": {
			statusCode:   http.StatusNotFound,
			responseBody: `{"code":404,"message":"bad API request, please contact support@snyk.io for assistance","error":"unsupported url"}`,
			expectedErr:  "bad API request, please contact support@snyk.io for assistance (404 Not Found)",
		},
		"500 Internal Server Error": {
			statusCode:   http.StatusInternalServerError,
			responseBody: `{"message":"Internal server error."}`,
			expectedErr:  "Internal server error. (500 Internal Server Error)",
		},
	}

	for name, tt := range tc {
		t.Run(name, func(t *testing.T) {
			mockHTTPClient := mocks.NewMockSBOMService(
				mocks.NewMockResponse(
					"application/json; charset=utf-8",
					[]byte(tt.responseBody),
					tt.statusCode))

			client := snykclient.NewSnykClient(mockHTTPClient.Client(), mockHTTPClient.URL, "org1")
			_, err := client.MonitorDependencies(context.Background(), errFactory, &exampleScanResult)

			assert.ErrorContains(t, err, strconv.Itoa(tt.statusCode))
			assert.ErrorContains(t, err, tt.expectedErr)
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
