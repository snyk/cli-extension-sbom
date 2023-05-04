package service

import (
	"bytes"
	"context"
	stderr "errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"

	"github.com/snyk/cli-extension-sbom/internal/errors"
)

type (
	SBOMResult struct {
		Doc      []byte
		MIMEType string
	}

	subject struct {
		name    string
		version string
	}
)

const (
	apiVersion   = "2022-03-31~experimental"
	MimeTypeJSON = "application/json"
)

var sbomFormats = [...]string{
	"cyclonedx1.4+json",
	"cyclonedx1.4+xml",
	"spdx2.3+json",
}

func NewSubject(name, version string) *subject {
	return &subject{
		name:    name,
		version: version,
	}
}

func DepGraphsToSBOM(
	client *http.Client,
	apiURL string,
	orgID string,
	depGraphs [][]byte,
	subject *subject,
	format string,
	logger *log.Logger,
	errFactory *errors.ErrorFactory,
) (result *SBOMResult, err error) {
	payload, err := preparePayload(depGraphs, subject)
	if err != nil {
		return nil, errFactory.NewInternalError(err)
	}

	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		buildURL(apiURL, orgID, format),
		bytes.NewBuffer(payload),
	)
	if err != nil {
		return nil, errFactory.NewInternalError(fmt.Errorf("error while creating request: %w", err))
	}
	req.Header.Add("Content-Type", MimeTypeJSON)

	logger.Printf("Converting depgraphs remotely (url: %s)", req.URL.String())

	resp, err := client.Do(req)
	if err != nil {
		return nil, errFactory.NewInternalError(fmt.Errorf("error while making request: %w", err))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errorFromResponse(resp, errFactory, orgID)
	}

	defer resp.Body.Close()
	doc, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errFactory.NewInternalError(fmt.Errorf("could not read response body: %w", err))
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

func errorFromResponse(resp *http.Response, errFactory *errors.ErrorFactory, orgID string) error {
	err := fmt.Errorf("could not convert to SBOM (status: %s)", resp.Status)
	switch resp.StatusCode {
	case http.StatusBadRequest:
		return errFactory.NewBadRequestError(err)
	case http.StatusUnauthorized:
		return errFactory.NewUnauthorizedError(err)
	case http.StatusForbidden:
		return errFactory.NewForbiddenError(err, orgID)
	default:
		return errFactory.NewRemoteError(err)
	}
}

func ValidateSBOMFormat(errFactory *errors.ErrorFactory, candidate string) error {
	if candidate == "" {
		return errFactory.NewEmptyFormatError(sbomFormats[:])
	}

	for _, f := range sbomFormats {
		if f == candidate {
			return nil
		}
	}

	return errFactory.NewInvalidFormatError(candidate, sbomFormats[:])
}

func preparePayload(depGraphs [][]byte, subject *subject) ([]byte, error) {
	if len(depGraphs) == 1 {
		return singleDepGraphReqBody(depGraphs[0]), nil
	} else {
		return multipleDepGraphsReqBody(depGraphs, subject)
	}
}

func singleDepGraphReqBody(depGraph []byte) []byte {
	return []byte(fmt.Sprintf(`{"depGraph":%s}`, depGraph))
}

func multipleDepGraphsReqBody(depGraphs [][]byte, subject *subject) ([]byte, error) {
	if subject == nil {
		return []byte{}, stderr.New("no subject defined for multiple depgraphs")
	}
	return []byte(fmt.Sprintf(
		`{"depGraphs":[%s],"subject":{"name":%q,"version":%q}}`,
		bytes.Join(depGraphs, []byte(",")),
		subject.name,
		subject.version,
	)), nil
}
