package snykclient_test

import (
	"bytes"
	_ "embed"
	"log"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-sbom/internal/errors"
	"github.com/snyk/cli-extension-sbom/internal/snykclient"
)

//go:embed testdata/sbom-test-result.response.json
var testResultMockResponse []byte

var logger = log.New(&bytes.Buffer{}, "", 0)
var errFactory = errors.NewErrorFactory(logger)

func TestNewSnykClient(t *testing.T) {
	client := snykclient.NewSnykClient(http.DefaultClient, "http://example.com", "org1")
	assert.NotNil(t, client)
}
