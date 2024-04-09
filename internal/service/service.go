package service

import (
	"bytes"
	"context"
	"encoding/json"
	stderr "errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	cli_errors "github.com/snyk/error-catalog-golang/cli"
	openapi_errors "github.com/snyk/error-catalog-golang/openapi"
	"github.com/snyk/error-catalog-golang/snyk_errors"
)

type (
	SBOMResult struct {
		Doc      []byte
		MIMEType string
	}

	Subject struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
)

const (
	apiVersion   = "2022-03-31~experimental"
	MimeTypeJSON = "application/json"
)

var sbomFormats = []string{
	"cyclonedx1.4+json",
	"cyclonedx1.4+xml",
	"cyclonedx1.5+json",
	"cyclonedx1.5+xml",
	"spdx2.3+json",
}

func NewSubject(name, version string) *Subject {
	return &Subject{
		Name:    name,
		Version: version,
	}
}

func DepGraphsToSBOM(
	client *http.Client,
	apiURL string,
	orgID string,
	depGraphs []json.RawMessage,
	subject *Subject,
	t *Tool,
	format string,
	logger *log.Logger,
) (result *SBOMResult, err error) {
	payload, err := preparePayload(depGraphs, subject, t)
	if err != nil {
		return nil, cli_errors.NewInternalServerError("", snyk_errors.WithCause(err))
	}

	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		buildURL(apiURL, orgID, format),
		bytes.NewBuffer(payload),
	)
	if err != nil {
		return nil, cli_errors.NewInternalServerError("", snyk_errors.WithCause(fmt.Errorf("error while creating request: %w", err)))
	}
	req.Header.Add("Content-Type", MimeTypeJSON)

	logger.Printf("Converting depgraphs remotely (url: %s)", req.URL.String())

	resp, err := client.Do(req)
	if err != nil {
		return nil, cli_errors.NewInternalServerError("", snyk_errors.WithCause(fmt.Errorf("error while making request: %w", err)))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errorFromResponse(resp, orgID)
	}

	defer resp.Body.Close()
	doc, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, cli_errors.NewInternalServerError("", snyk_errors.WithCause(fmt.Errorf("could not read response body: %w", err)))
	}

	logger.Println("Successfully converted depGraph to SBOM")

	return &SBOMResult{Doc: doc, MIMEType: resp.Header.Get("Content-Type")}, nil
}

func buildURL(apiURL, orgID, format string) string {
	return fmt.Sprintf(
		"%s/hidden/orgs/%s/sbom?version=%s&format=%s",
		apiURL, orgID, apiVersion, url.QueryEscape(format),
	)
}

func errorFromResponse(resp *http.Response, orgID string) error {
	err := fmt.Errorf("could not convert to SBOM (status: %s)", resp.Status)
	switch resp.StatusCode {
	case http.StatusBadRequest:
		return openapi_errors.NewBadRequestError("", snyk_errors.WithCause(err))
	case http.StatusUnauthorized:
		return openapi_errors.NewUnauthorizedError("", snyk_errors.WithCause(err))
	case http.StatusForbidden:
		return openapi_errors.NewForbiddenError(orgID, snyk_errors.WithCause(err))
	default:
		return cli_errors.NewInternalServerError(
			"An error occurred while generating the SBOM. Should this issue persist, please reach out to customer support.",
			snyk_errors.WithCause(err),
		)
	}
}

func ValidateSBOMFormat(candidate string) error {
	if candidate == "" {
		return cli_errors.NewMissingFormatFlagError("Flag `--format` is required to execute this command. Value should be a supported format.")
	}

	for _, f := range sbomFormats {
		if f == candidate {
			return nil
		}
	}

	return cli_errors.NewUnsupportedSBOMFormatError(fmt.Sprintf("Supported formats are: %s", strings.Join(sbomFormats, ",")))
}

func preparePayload(depGraphs []json.RawMessage, subject *Subject, t *Tool) ([]byte, error) {
	// by using json.RawMessage everywhere we expect a json-encoded []byte, we can embed this
	// directly in Go types and call `json.Marshal` on it to embed the JSON directly.

	// only send the request with a single depGraph if there's no subject. If there is a subject, we
	// want to use the multi-depgraph-endpoint so that we can overwrite the depGraph's name &
	// version with the name & version from the subject.
	if subject == nil || subject.Name == "" {
		if len(depGraphs) != 1 {
			return []byte{}, stderr.New("no subject defined for multiple depgraphs")
		}

		return json.Marshal(&payloadSingleDepGraph{
			Tools:    []*Tool{t},
			DepGraph: depGraphs[0],
		})
	}

	return json.Marshal(&payloadMultipleDepGraphs{
		Tools:     []*Tool{t},
		DepGraphs: depGraphs,
		Subject:   subject,
	})
}
