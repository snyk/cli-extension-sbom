package service

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"

	"github.com/snyk/cli-extension-sbom/internal/errors"
)

type SBOMResult struct {
	Doc      []byte
	MIMEType string
}

const (
	apiVersion   = "2022-03-31~experimental"
	MimeTypeJSON = "application/json"
)

var sbomFormats = [...]string{
	"cyclonedx1.4+json",
	"cyclonedx1.4+xml",
	"spdx2.3+json",
}

func DepGraphToSBOM(
	client *http.Client,
	apiURL string,
	orgID string,
	depGraph []byte,
	format string,
	logger *log.Logger,
	errFactory *errors.ErrorFactory,
) (result *SBOMResult, err error) {
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		buildURL(apiURL, orgID, format),
		bytes.NewBuffer([]byte(fmt.Sprintf(`{"depGraph":%s}`, depGraph))),
	)
	if err != nil {
		return nil, errFactory.NewInternalError(fmt.Errorf("error while creating request: %w", err))
	}
	req.Header.Add("Content-Type", MimeTypeJSON)

	logger.Printf("Converting depgraph remotely (url: %s)", req.URL.String())

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
