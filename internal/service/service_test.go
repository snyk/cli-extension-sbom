package service_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-sbom/internal/errors"
	"github.com/snyk/cli-extension-sbom/internal/mocks"
	. "github.com/snyk/cli-extension-sbom/internal/service"
)

const orgID = "c32727e4-2d6c-4780-aa1a-a89bcd16fe6f"

func TestDepGraphsToSBOM(t *testing.T) {
	tc := map[string]struct {
		format              string
		expectedContentType string
		mockBody            []byte
	}{
		"CycloneDX 1.4 JSON": {
			format:              "cyclonedx1.4+json",
			expectedContentType: "application/vnd.cyclonedx+json",
			mockBody:            []byte("{}"),
		},
		"CycloneDX 1.4 XML": {
			format:              "cyclonedx1.4+xml",
			expectedContentType: "application/vnd.cyclonedx+xml",
			mockBody:            []byte("<?xml ?>"),
		},
		"SPDX 2.3 JSON": {
			format:              "spdx2.3+json",
			expectedContentType: "application/json",
			mockBody:            []byte("{}"),
		},
	}

	for name, tt := range tc {
		t.Run(name, func(t *testing.T) {
			response := mocks.NewMockResponse(tt.expectedContentType, tt.mockBody, http.StatusOK)
			mockSBOMService := mocks.NewMockSBOMService(response, func(r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, MimeTypeJSON, r.Header.Get("Content-Type"))
				assert.Equal(
					t,
					fmt.Sprintf("/hidden/orgs/c32727e4-2d6c-4780-aa1a-a89bcd16fe6f/sbom?version=2022-03-31~experimental&format=%s", url.QueryEscape(tt.format)),
					r.RequestURI,
				)
			})
			logger := log.New(&bytes.Buffer{}, "", 0)
			errFactory := errors.NewErrorFactory(logger)

			res, err := DepGraphsToSBOM(
				http.DefaultClient,
				mockSBOMService.URL,
				orgID,
				[]json.RawMessage{[]byte("{}")},
				nil,
				nil,
				tt.format,
				logger,
				errFactory,
			)
			assert.NoError(t, err)
			assert.Equal(t, tt.mockBody, res.Doc)
			assert.Equal(t, tt.expectedContentType, res.MIMEType)
		})
	}
}

func TestDepGraphsToSBOM_MultipleDepGraphs(t *testing.T) {
	format := "cyclonedx1.4+json"
	expectedContentType := "application/vnd.cyclonedx+json"
	mockBody := []byte("{}")
	response := mocks.NewMockResponse(expectedContentType, mockBody, http.StatusOK)
	mockSBOMService := mocks.NewMockSBOMService(response, func(r *http.Request) {
		body, err := io.ReadAll(r.Body)
		defer r.Body.Close()
		require.NoError(t, err)
		assert.JSONEq(t, `{"depGraphs":[{},{}],"subject":{"name":"goof","version":"0.0.0"},`+
			`"tools":[{"name":"snyk-cli","vendor":"Snyk","version":"1.2.3"}]}`,
			string(body))
	})
	logger := log.New(&bytes.Buffer{}, "", 0)
	errFactory := errors.NewErrorFactory(logger)
	depGraphs := []json.RawMessage{[]byte("{}"), []byte("{}")}
	subject := NewSubject("goof", "0.0.0")
	tool := &Tool{Vendor: "Snyk", Name: "snyk-cli", Version: "1.2.3"}

	_, err := DepGraphsToSBOM(
		http.DefaultClient,
		mockSBOMService.URL,
		orgID,
		depGraphs,
		subject,
		tool,
		format,
		logger,
		errFactory,
	)
	assert.NoError(t, err)
}

func TestDepGraphsToSBOM_SingleDepGraph_WithSubject(t *testing.T) {
	format := "cyclonedx1.4+json"
	expectedContentType := "application/vnd.cyclonedx+json"
	mockBody := []byte("{}")
	response := mocks.NewMockResponse(expectedContentType, mockBody, http.StatusOK)
	mockSBOMService := mocks.NewMockSBOMService(response, func(r *http.Request) {
		body, err := io.ReadAll(r.Body)
		defer r.Body.Close()
		require.NoError(t, err)
		assert.JSONEq(t, `{"depGraphs":[{}],"subject":{"name":"goof","version":"0.0.0"},`+
			`"tools":[{"name":"snyk-cli","vendor":"Snyk","version":"1.2.3"}]}`,
			string(body))
	})
	logger := log.New(&bytes.Buffer{}, "", 0)
	errFactory := errors.NewErrorFactory(logger)
	depGraphs := []json.RawMessage{[]byte("{}")}
	subject := NewSubject("goof", "0.0.0")
	tool := &Tool{Vendor: "Snyk", Name: "snyk-cli", Version: "1.2.3"}

	_, err := DepGraphsToSBOM(
		http.DefaultClient,
		mockSBOMService.URL,
		orgID,
		depGraphs,
		subject,
		tool,
		format,
		logger,
		errFactory,
	)
	assert.NoError(t, err)
}

func TestDepGraphsToSBOM_FailedRequest(t *testing.T) {
	logger := log.New(&bytes.Buffer{}, "", 0)
	errFactory := errors.NewErrorFactory(logger)

	res, err := DepGraphsToSBOM(
		http.DefaultClient,
		"http://0.0.0.0",
		orgID,
		[]json.RawMessage{[]byte("{}")},
		nil,
		nil,
		"cyclonedx1.4+json",
		logger,
		errFactory,
	)

	assert.Nil(t, res)
	assert.ErrorContains(t, err, "An error occurred while running the underlying analysis which is required to generate the SBOM. "+
		"Should this issue persist, please reach out to customer support.")
}

func TestDepGraphsToSBOM_UnsuccessfulResponse(t *testing.T) {
	tc := map[string]struct {
		statusCode  int
		expectedErr string
	}{
		"Bad Request": {
			statusCode: http.StatusBadRequest,
			expectedErr: "SBOM generation failed due to bad input arguments. " +
				"Please make sure you are using the latest version of the Snyk CLI.",
		},
		"Unauthorized": {
			statusCode: http.StatusUnauthorized,
			expectedErr: "Snyk failed to authenticate you based on on you API token. " +
				"Please ensure that you have authenticated by running `snyk auth`.",
		},
		"Forbidden": {
			statusCode: http.StatusForbidden,
			expectedErr: "Your account is not authorized to perform this action. " +
				"Please ensure that you belong to the given organization and that the organization is " +
				"entitled to use the Snyk API. (Org ID: c32727e4-2d6c-4780-aa1a-a89bcd16fe6f)",
		},
		"Other Errors": {
			statusCode: http.StatusInternalServerError,
			expectedErr: "An error occurred while generating the SBOM. Should this issue persist, " +
				"please reach out to customer support.",
		},
	}

	for name, tt := range tc {
		t.Run(name, func(t *testing.T) {
			response := mocks.NewMockResponse("text/plain", []byte{}, tt.statusCode)
			mockSBOMService := mocks.NewMockSBOMService(response)
			logger := log.New(&bytes.Buffer{}, "", 0)
			errFactory := errors.NewErrorFactory(logger)

			_, err := DepGraphsToSBOM(
				http.DefaultClient,
				mockSBOMService.URL,
				orgID,
				[]json.RawMessage{[]byte("{}")},
				nil,
				nil,
				"cyclonedx1.4+json",
				logger,
				errFactory,
			)
			assert.Error(t, err)
			assert.ErrorContains(t, err, tt.expectedErr)
		})
	}
}

func TestValidateSBOMFormat_EmptyFormat(t *testing.T) {
	logger := log.New(&bytes.Buffer{}, "", 0)
	errFactory := errors.NewErrorFactory(logger)
	err := ValidateSBOMFormat(errFactory, "")
	assert.ErrorContains(t, err, "Must set `--format` flag to specify an SBOM format. "+
		"Available formats are: cyclonedx1.4+json, cyclonedx1.4+xml, spdx2.3+json")
}

func TestValidateSBOMFormat_InvalidFormat(t *testing.T) {
	logger := log.New(&bytes.Buffer{}, "", 0)
	errFactory := errors.NewErrorFactory(logger)
	err := ValidateSBOMFormat(errFactory, "not+a+format")
	assert.ErrorContains(t, err, "The format provided (not+a+format) is not one of the available formats. "+
		"Available formats are: cyclonedx1.4+json, cyclonedx1.4+xml, spdx2.3+json")
}
