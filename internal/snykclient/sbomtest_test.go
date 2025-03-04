package snykclient_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	snyk_errors "github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-sbom/internal/mocks"
	"github.com/snyk/cli-extension-sbom/internal/snykclient"
)

func TestSnykClient_CreateSBOMTest(t *testing.T) {
	response := mocks.NewMockResponse(
		"application/vnd.api+json",
		[]byte(`{"data": {"id": "test-id"}}`),
		http.StatusCreated,
	)
	sbomContent := `{"foo":"bar"}`
	expectedRequestBody := `{"data":{"type":"sbom_test","attributes":{"sbom":` + sbomContent + `}}}`

	mockHTTPClient := mocks.NewMockSBOMService(response, func(r *http.Request) {
		assert.Equal(t, "/rest/orgs/org1/sbom_tests?version=2024-07-10~beta", r.RequestURI)
		assert.Equal(t, "application/vnd.api+json", r.Header.Get("Content-Type"))

		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)

		assert.Equal(t, expectedRequestBody, string(body))
	})

	client := snykclient.NewSnykClient(mockHTTPClient.Client(), mockHTTPClient.URL, "org1")

	sbomTest, err := client.CreateSBOMTest(context.Background(), []byte(sbomContent), errFactory)

	assert.NoError(t, err)
	assert.Equal(t, "test-id", sbomTest.ID)
}

func TestSnykClient_GetSBOMTestStatus_RedirectToResults(t *testing.T) {
	response := mocks.NewMockResponseWithHeaders(
		"application/vnd.api+json",
		[]byte{},
		http.StatusSeeOther,
		http.Header{
			"Location": {"/rest/orgs/org1/sbom_tests/test-id/results?version=2024-07-10~beta"},
		},
	)

	mockHTTPClient := mocks.NewMockSBOMService(response, func(r *http.Request) {
		// should not follow redirects - using `require` to fail the test fast
		require.Equal(t, "/rest/orgs/org1/sbom_tests/test-id?version=2024-07-10~beta", r.RequestURI)
	})

	snykClient := snykclient.NewSnykClient(mockHTTPClient.Client(), mockHTTPClient.URL, "org1")
	sbomTest := &snykclient.SBOMTest{
		SnykClient: snykClient,
		ID:         "test-id",
	}

	status, err := sbomTest.GetStatus(context.Background(), errFactory)

	assert.NoError(t, err)
	assert.Equal(t, snykclient.SBOMTestStatusFinished, status)
}

func TestSnykClient_GetSBOMTestStatus_Processing(t *testing.T) {
	response := mocks.NewMockResponse(
		"application/vnd.api+json",
		[]byte(`{"data":{"id":"123","type":"sbom_tests","attributes":{"status":"processing"}},"jsonapi":{"version":"1.0"}}`),
		http.StatusOK,
	)

	mockHTTPClient := mocks.NewMockSBOMService(response, func(r *http.Request) {
		assert.Equal(t, "/rest/orgs/org1/sbom_tests/test-id?version=2024-07-10~beta", r.RequestURI)
	})

	snykClient := snykclient.NewSnykClient(mockHTTPClient.Client(), mockHTTPClient.URL, "org1")
	sbomTest := &snykclient.SBOMTest{
		SnykClient: snykClient,
		ID:         "test-id",
	}

	status, err := sbomTest.GetStatus(context.Background(), errFactory)

	assert.NoError(t, err)
	assert.Equal(t, snykclient.SBOMTestStatusProcessing, status)
}

func TestSnykClient_GetSBOMTestStatus_Error(t *testing.T) {
	response := mocks.NewMockResponse(
		"application/vnd.api+json",
		[]byte(`{"data":{"id":"123","type":"sbom_tests","attributes":{"status":"error"}},"jsonapi":{"version":"1.0"}}`),
		http.StatusOK,
	)

	mockHTTPClient := mocks.NewMockSBOMService(response, func(r *http.Request) {
		assert.Equal(t, "/rest/orgs/org1/sbom_tests/test-id?version=2024-07-10~beta", r.RequestURI)
	})

	snykClient := snykclient.NewSnykClient(mockHTTPClient.Client(), mockHTTPClient.URL, "org1")
	sbomTest := &snykclient.SBOMTest{
		SnykClient: snykClient,
		ID:         "test-id",
	}

	status, err := sbomTest.GetStatus(context.Background(), errFactory)

	assert.NoError(t, err)
	assert.Equal(t, snykclient.SBOMTestStatusError, status)
}

func TestSnykClient_GetSBOMTestResults(t *testing.T) {
	response := mocks.NewMockResponse(
		"application/vnd.api+json",
		testResultMockResponse,
		http.StatusOK,
	)

	mockHTTPClient := mocks.NewMockSBOMService(response, func(r *http.Request) {
		assert.Equal(t, "/rest/orgs/org1/sbom_tests/test-id/results?version=2024-07-10~beta", r.RequestURI)
	})

	snykClient := snykclient.NewSnykClient(mockHTTPClient.Client(), mockHTTPClient.URL, "org1")
	sbomTest := &snykclient.SBOMTest{
		SnykClient: snykClient,
		ID:         "test-id",
	}

	result, err := sbomTest.GetResult(context.Background(), errFactory)

	assert.NoError(t, err)
	assert.Equal(t, 133, result.Summary.TotalIssues)
}

var backoff = func() {}

func TestSBOMTest_WaitUntilComplete(t *testing.T) {
	var numRequests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { numRequests++ }()
		if numRequests < 5 {
			//nolint:errcheck // No need to test the mock server write err
			w.Write([]byte(`{"data":{"id":"123","type":"sbom_tests","attributes":{"status":"processing"}},"jsonapi":{"version":"1.0"}}`))
			return
		}
		w.Header().Add("Location", "https://:")
		w.WriteHeader(http.StatusSeeOther)
	}))
	snykClient := snykclient.NewSnykClient(srv.Client(), srv.URL, "org1")
	sbomTest := &snykclient.SBOMTest{
		SnykClient: snykClient,
		ID:         "test-id",
	}

	err := sbomTest.WaitUntilCompleteWithBackoff(context.Background(), backoff, errFactory)

	assert.NoError(t, err)
	assert.Equal(t, numRequests, 6)
}

func TestSBOMTest_WaitUntilCompleteErrors(t *testing.T) {
	var numRequests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { numRequests++ }()
		if numRequests < 5 {
			//nolint:errcheck // No need to test the mock server write err
			w.Write([]byte(`{"data":{"id":"123","type":"sbom_tests","attributes":{"status":"processing"}},"jsonapi":{"version":"1.0"}}`))
			return
		}
		w.WriteHeader(http.StatusBadGateway)
	}))
	snykClient := snykclient.NewSnykClient(srv.Client(), srv.URL, "org1")
	sbomTest := &snykclient.SBOMTest{
		SnykClient: snykClient,
		ID:         "test-id",
	}

	err := sbomTest.WaitUntilCompleteWithBackoff(context.Background(), backoff, errFactory)

	assert.ErrorContains(t, err, "Failed to test SBOM. There was an error when trying to test your SBOM, retrying may resolve the issue. "+
		"If the error still occurs, contact support.")
	assert.Equal(t, numRequests, 6)
}

func TestSnykClient_ServerError(t *testing.T) {
	response := mocks.NewMockResponse(
		"application/vnd.api+json",
		[]byte{},
		http.StatusBadGateway,
	)

	mockHTTPClient := mocks.NewMockSBOMService(response)

	snykClient := snykclient.NewSnykClient(mockHTTPClient.Client(), mockHTTPClient.URL, "org1")
	sbomTest := &snykclient.SBOMTest{
		SnykClient: snykClient,
		ID:         "test-id",
	}

	status, err := sbomTest.GetStatus(context.Background(), errFactory)

	assert.ErrorContains(t, err, "unexpected status code")
	assert.Equal(t, snykclient.SBOMTestStatusIndeterminate, status)
}

func TestSnykClient_ErrorCatalogError(t *testing.T) {
	response := mocks.NewMockResponse(
		"application/vnd.api+json",
		[]byte(`{
			"jsonapi":{"version":"1.0"},
			"errors":[{
				"id":"ce2b3dc4-415d-4d47-97e2-2e5de2337524",
				"title":"Unknown SBOM format",
				"status":"422",
				"code":"SNYK-SBOM-0006",
				"meta":{"classification":"UNSUPPORTED","isErrorCatalogError":true},
				"links":{"about":"https://docs.snyk.io/scan-with-snyk/error-catalog#snyk-sbom-0006"},
				"source":{}
			}]
		}`),
		http.StatusUnprocessableEntity,
	)

	mockHTTPClient := mocks.NewMockSBOMService(response)

	snykClient := snykclient.NewSnykClient(mockHTTPClient.Client(), mockHTTPClient.URL, "org1")
	sbomTest := &snykclient.SBOMTest{
		SnykClient: snykClient,
		ID:         "test-id",
	}

	status, err := sbomTest.GetStatus(context.Background(), errFactory)

	assert.ErrorAs(t, err, &snyk_errors.Error{})
	assert.ErrorContains(t, err, "Unknown SBOM format")
	assert.Equal(t, snykclient.SBOMTestStatusError, status)
}
