package service_test

import (
	"bytes"
	"log"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-sbom/internal/mocks"
	. "github.com/snyk/cli-extension-sbom/internal/service"
)

func TestDepGraphToSBOM(t *testing.T) {
	response := []byte("{}")
	mockSBOMService := mocks.NewMockSBOMService(response, func(r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, MimeTypeJSON, r.Header.Get("Content-Type"))
		assert.Equal(t, "/hidden/orgs/c32727e4-2d6c-4780-aa1a-a89bcd16fe6f/sbom?version=2022-03-31~experimental&format=cyclonedx%2Bjson", r.RequestURI)
	})
	orgID := "c32727e4-2d6c-4780-aa1a-a89bcd16fe6f"
	logger := log.New(&bytes.Buffer{}, "", 0)

	doc, err := DepGraphToSBOM(
		http.DefaultClient,
		mockSBOMService.URL,
		orgID,
		[]byte("{}"),
		"cyclonedx+json",
		logger,
	)
	assert.NoError(t, err)
	assert.Equal(t, response, doc)
}
