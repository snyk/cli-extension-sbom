package service_test

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-sbom/internal/mocks"
	. "github.com/snyk/cli-extension-sbom/internal/service"
)

const orgID = "c32727e4-2d6c-4780-aa1a-a89bcd16fe6f"

func TestDepGraphToSBOM(t *testing.T) {
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
			response := mocks.NewMockResponse(tt.expectedContentType, tt.mockBody)
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

			res, err := DepGraphToSBOM(
				http.DefaultClient,
				mockSBOMService.URL,
				orgID,
				[]byte("{}"),
				tt.format,
				logger,
			)
			assert.NoError(t, err)
			assert.Equal(t, tt.mockBody, res.Doc)
			assert.Equal(t, tt.expectedContentType, res.MIMEType)
		})
	}
}

func TestValidateSBOMFormat_EmptyFormat(t *testing.T) {
	err := ValidateSBOMFormat("")
	assert.ErrorContains(t, err, "Must set `--format` flag to specify an SBOM format. "+
		"Available formats are: cyclonedx1.4+json, cyclonedx1.4+xml, spdx2.3+json")
}

func TestValidateSBOMFormat_InvalidFormat(t *testing.T) {
	err := ValidateSBOMFormat("not+a+format")
	assert.ErrorContains(t, err, "The format provided (not+a+format) is not one of the available formats. "+
		"Available formats are: cyclonedx1.4+json, cyclonedx1.4+xml, spdx2.3+json")
}
