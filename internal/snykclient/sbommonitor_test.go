package snykclient_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-sbom/internal/mocks"
	"github.com/snyk/cli-extension-sbom/internal/snykclient"
)

func Test_CreateSBOMMonitor(t *testing.T) {
	tc := []struct {
		filename            string
		expectedRequestBody string
	}{
		{
			filename:            "project.sbom.json",
			expectedRequestBody: `{"data":{"attributes":{"sbom":"{\"foo\":\"bar\"}","filename":"project.sbom.json"},"type":"sbom_monitor"}}`,
		},
		{
			filename:            "/home/myuser/project/project.sbom.json",
			expectedRequestBody: `{"data":{"attributes":{"sbom":"{\"foo\":\"bar\"}","filename":"project.sbom.json"},"type":"sbom_monitor"}}`,
		},
		{
			filename:            "",
			expectedRequestBody: `{"data":{"attributes":{"sbom":"{\"foo\":\"bar\"}"},"type":"sbom_monitor"}}`,
		},
	}

	for _, tt := range tc {
		t.Run(tt.filename, func(t *testing.T) {
			response := mocks.NewMockResponse(
				"application/vnd.api+json",
				[]byte(`{"data": {"id": "test-id"}}`),
				http.StatusCreated,
			)
			sbomContent := `{"foo":"bar"}`

			mockHTTPClient := mocks.NewMockSBOMService(response, func(r *http.Request) {
				assert.Equal(t, "/closed-beta/orgs/org1/sbom_monitors?version=2024-07-10~beta", r.RequestURI)
				assert.Equal(t, "application/vnd.api+json", r.Header.Get("Content-Type"))

				body, err := io.ReadAll(r.Body)
				assert.NoError(t, err)

				assert.Equal(t, tt.expectedRequestBody, string(body))
			})

			client := snykclient.NewSnykClient(mockHTTPClient.Client(), mockHTTPClient.URL, "org1")

			sbomMonitor, err := client.CreateSBOMMonitor(context.Background(), []byte(sbomContent), "", tt.filename, errFactory)

			assert.NoError(t, err)
			assert.Equal(t, "test-id", sbomMonitor.ID)
		})
	}
}

func TestSBOMMonitor_WaitUntilComplete(t *testing.T) {
	getMonitorResponse := `{"data":{"id":"123","type":"sbom_monitor","attributes":{"state":"%s"}},"jsonapi":{"version":"1.0"}}`

	var numRequests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { numRequests++ }()
		if numRequests < 5 {
			fmt.Fprintf(w, getMonitorResponse, snykclient.SBOMMonitorStateProcessing)
			return
		}
		fmt.Fprintf(w, getMonitorResponse, snykclient.SBOMMonitorStateComplete)
		w.WriteHeader(http.StatusOK)
	}))
	snykClient := snykclient.NewSnykClient(srv.Client(), srv.URL, "org1")
	sbomMonitor := &snykclient.SBOMMonitor{
		SnykClient: snykClient,
		ID:         "test-id",
	}

	err := sbomMonitor.WaitUntilCompleteWithBackoff(context.Background(), backoff, errFactory)

	assert.NoError(t, err)
	assert.Equal(t, numRequests, 6)
}

func TestSBOMMonitor_WaitUntilCompleteErrors(t *testing.T) {
	getMonitorResponse := `{"data":{"id":"123","type":"sbom_monitor","attributes":{"state":"%s"}},"jsonapi":{"version":"1.0"}}`

	var numRequests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { numRequests++ }()
		if numRequests < 5 {
			fmt.Fprintf(w, getMonitorResponse, snykclient.SBOMMonitorStateProcessing)
			return
		}
		w.WriteHeader(http.StatusBadGateway)
	}))
	snykClient := snykclient.NewSnykClient(srv.Client(), srv.URL, "org1")
	sbomMonitor := &snykclient.SBOMMonitor{
		SnykClient: snykClient,
		ID:         "test-id",
	}

	err := sbomMonitor.WaitUntilCompleteWithBackoff(context.Background(), backoff, errFactory)

	assert.ErrorContains(t, err, "Failed to monitor SBOM. There was an error when trying to monitor your SBOM, retrying may resolve the issue. "+
		"If the error still occurs, contact support.")
	assert.Equal(t, numRequests, 6)
}
