package snykclient_test

import (
	"bytes"
	"context"
	_ "embed"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-sbom/internal/errors"
	"github.com/snyk/cli-extension-sbom/internal/mocks"
	. "github.com/snyk/cli-extension-sbom/internal/snykclient"
)

//go:embed testdata/sbom-test-result.response.json
var testResultMockResponse []byte

func TestNewSnykClient(t *testing.T) {
	client := NewSnykClient(http.DefaultClient, "http://example.com", "org1")
	assert.NotNil(t, client)
}

func TestSnykClient_CreateSBOMTest(t *testing.T) {
	response := mocks.NewMockResponse(
		"application/vnd.api+json",
		[]byte(`{"data": {"id": "test-id"}}`),
		http.StatusCreated,
	)
	sbomContent := `{"foo":"bar"}`
	expectedRequestBody := `{"data":{"type":"sbom_test","attributes":{"sbom":` + sbomContent + `}}}`

	mockHTTPClient := mocks.NewMockSBOMService(response, func(r *http.Request) {
		assert.Equal(t, "/rest/orgs/org1/sbom_tests?version=2023-08-31~beta", r.RequestURI)
		assert.Equal(t, "application/vnd.api+json", r.Header.Get("Content-Type"))

		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)

		assert.Equal(t, expectedRequestBody, string(body))
	})

	client := NewSnykClient(mockHTTPClient.Client(), mockHTTPClient.URL, "org1")
	logger := log.New(&bytes.Buffer{}, "", 0)
	errFactory := errors.NewErrorFactory(logger)
	sbomTest, err := client.CreateSBOMTest(context.Background(), []byte(sbomContent), errFactory)

	assert.NoError(t, err)
	assert.Equal(t, "test-id", sbomTest.ID)
}

func TestSnykClient_GetStatus_RedirectToResults(t *testing.T) {
	response := mocks.NewMockResponseWithHeaders(
		"application/vnd.api+json",
		[]byte{},
		http.StatusSeeOther,
		http.Header{
			"Location": {"/rest/orgs/org1/sbom_tests/test-id/results?version=2023-08-31~beta"},
		},
	)

	mockHTTPClient := mocks.NewMockSBOMService(response, func(r *http.Request) {
		// should not follow redirects - using `require` to fail the test fast
		require.Equal(t, "/rest/orgs/org1/sbom_tests/test-id?version=2023-08-31~beta", r.RequestURI)
	})

	snykClient := NewSnykClient(mockHTTPClient.Client(), mockHTTPClient.URL, "org1")
	sbomTest := &SBOMTest{
		SnykClient: snykClient,
		ID:         "test-id",
	}
	logger := log.New(&bytes.Buffer{}, "", 0)
	errFactory := errors.NewErrorFactory(logger)
	status, err := sbomTest.GetStatus(context.Background(), errFactory)

	assert.NoError(t, err)
	assert.Equal(t, SBOMTestStatusFinished, status)
}

func TestSnykClient_GetStatus_Processing(t *testing.T) {
	response := mocks.NewMockResponse(
		"application/vnd.api+json",
		[]byte(`{"data":{"id":"123","type":"sbom_tests","attributes":{"status":"processing"}},"jsonapi":{"version":"1.0"}}`),
		http.StatusOK,
	)

	mockHTTPClient := mocks.NewMockSBOMService(response, func(r *http.Request) {
		assert.Equal(t, "/rest/orgs/org1/sbom_tests/test-id?version=2023-08-31~beta", r.RequestURI)
	})

	snykClient := NewSnykClient(mockHTTPClient.Client(), mockHTTPClient.URL, "org1")
	sbomTest := &SBOMTest{
		SnykClient: snykClient,
		ID:         "test-id",
	}

	logger := log.New(&bytes.Buffer{}, "", 0)
	errFactory := errors.NewErrorFactory(logger)

	status, err := sbomTest.GetStatus(context.Background(), errFactory)

	assert.NoError(t, err)
	assert.Equal(t, SBOMTestStatusProcessing, status)
}

func TestSnykClient_GetStatus_Error(t *testing.T) {
	response := mocks.NewMockResponse(
		"application/vnd.api+json",
		[]byte(`{"data":{"id":"123","type":"sbom_tests","attributes":{"status":"error"}},"jsonapi":{"version":"1.0"}}`),
		http.StatusOK,
	)

	mockHTTPClient := mocks.NewMockSBOMService(response, func(r *http.Request) {
		assert.Equal(t, "/rest/orgs/org1/sbom_tests/test-id?version=2023-08-31~beta", r.RequestURI)
	})

	snykClient := NewSnykClient(mockHTTPClient.Client(), mockHTTPClient.URL, "org1")
	sbomTest := &SBOMTest{
		SnykClient: snykClient,
		ID:         "test-id",
	}

	logger := log.New(&bytes.Buffer{}, "", 0)
	errFactory := errors.NewErrorFactory(logger)

	status, err := sbomTest.GetStatus(context.Background(), errFactory)

	assert.NoError(t, err)
	assert.Equal(t, SBOMTestStatusError, status)
}

func TestSnykClient_ServerError(t *testing.T) {
	response := mocks.NewMockResponse(
		"application/vnd.api+json",
		[]byte{},
		http.StatusBadGateway,
	)

	mockHTTPClient := mocks.NewMockSBOMService(response)

	snykClient := NewSnykClient(mockHTTPClient.Client(), mockHTTPClient.URL, "org1")
	sbomTest := &SBOMTest{
		SnykClient: snykClient,
		ID:         "test-id",
	}

	logger := log.New(&bytes.Buffer{}, "", 0)
	errFactory := errors.NewErrorFactory(logger)

	status, err := sbomTest.GetStatus(context.Background(), errFactory)

	assert.ErrorContains(t, err, "unexpected status code")
	assert.Equal(t, SBOMTestStatusIndeterminate, status)
}

func TestSnykClient_GetResults(t *testing.T) {
	response := mocks.NewMockResponse(
		"application/vnd.api+json",
		testResultMockResponse,
		http.StatusOK,
	)

	mockHTTPClient := mocks.NewMockSBOMService(response, func(r *http.Request) {
		assert.Equal(t, "/rest/orgs/org1/sbom_tests/test-id/results?version=2023-08-31~beta", r.RequestURI)
	})

	snykClient := NewSnykClient(mockHTTPClient.Client(), mockHTTPClient.URL, "org1")
	sbomTest := &SBOMTest{
		SnykClient: snykClient,
		ID:         "test-id",
	}

	logger := log.New(&bytes.Buffer{}, "", 0)
	errFactory := errors.NewErrorFactory(logger)

	result, err := sbomTest.GetResult(context.Background(), errFactory)

	assert.NoError(t, err)
	assert.Equal(t, 42, result.Data.Attributes.Summary.TotalIssues)
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
	snykClient := NewSnykClient(srv.Client(), srv.URL, "org1")
	sbomTest := &SBOMTest{
		SnykClient: snykClient,
		ID:         "test-id",
	}

	logger := log.New(&bytes.Buffer{}, "", 0)
	errFactory := errors.NewErrorFactory(logger)

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
	snykClient := NewSnykClient(srv.Client(), srv.URL, "org1")
	sbomTest := &SBOMTest{
		SnykClient: snykClient,
		ID:         "test-id",
	}

	logger := log.New(&bytes.Buffer{}, "", 0)
	errFactory := errors.NewErrorFactory(logger)

	err := sbomTest.WaitUntilCompleteWithBackoff(context.Background(), backoff, errFactory)

	assert.ErrorContains(t, err, "An error occurred while running the underlying analysis which is required to generate the SBOM. "+
		"Should this issue persist, please reach out to customer support.")
	assert.Equal(t, numRequests, 6)
}
