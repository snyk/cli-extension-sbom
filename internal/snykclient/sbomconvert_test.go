package snykclient_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-sbom/internal/mocks"
	"github.com/snyk/cli-extension-sbom/internal/snykclient"
)

func Test_SBOMConvert(t *testing.T) {
	response := mocks.NewMockResponse(
		"application/json; charset=utf-8",
		[]byte(`{"scanResults":[{"name":"Scan 1"},{"name":"Scan 2"}]}`),
		http.StatusOK,
	)

	sbomContent := `{"foo":"bar"}`

	mockHTTPClient := mocks.NewMockSBOMService(response, func(r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/hidden/orgs/org1/sboms/convert?version=2025-03-06", r.RequestURI)
		assert.Equal(t, "application/octet-stream", r.Header.Get("Content-Type"))
	})

	client := snykclient.NewSnykClient(mockHTTPClient.Client(), mockHTTPClient.URL, "org1")
	depsResp, err := client.SBOMConvert(
		context.Background(),
		errFactory,
		bytes.NewBuffer([]byte(sbomContent)),
	)

	assert.NoError(t, err)
	assert.Equal(t, 2, len(depsResp))
	assert.Equal(t, "Scan 1", depsResp[0].Name)
	assert.Equal(t, "Scan 2", depsResp[1].Name)
}

func Test_SBOMConvert_InvalidJSONReturned(t *testing.T) {
	response := mocks.NewMockResponse(
		"application/json; charset=utf-8",
		[]byte(`{"scanResults":[{"name":"Scan 1"`),
		http.StatusOK,
	)

	mockHTTPClient := mocks.NewMockSBOMService(response)

	client := snykclient.NewSnykClient(mockHTTPClient.Client(), mockHTTPClient.URL, "org1")
	_, err := client.SBOMConvert(
		context.Background(),
		errFactory,
		strings.NewReader(`{"foo":"bar"}`))

	assert.ErrorContains(t, err, "unexpected EOF")
}

func Test_SBOMConvert_ServerErrors(t *testing.T) {
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

	sbomContent := `{"foo":"bar"}`

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			response := mocks.NewMockResponse(
				"application/json; charset=utf-8",
				[]byte(tc.responseBody),
				tc.statusCode,
			)

			mockHTTPClient := mocks.NewMockSBOMService(response)

			client := snykclient.NewSnykClient(mockHTTPClient.Client(), mockHTTPClient.URL, "org1")
			_, err := client.SBOMConvert(context.Background(), errFactory, bytes.NewBufferString(sbomContent))

			assert.ErrorContainsf(
				t,
				err,
				fmt.Sprintf("%d", tc.statusCode),
				"Expected error to contain status code %d",
				tc.statusCode,
			)
		})
	}
}
