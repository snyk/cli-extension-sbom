package service

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/snyk/cli-extension-sbom/internal/extension_errors"
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
) (result *SBOMResult, err error) {
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		buildURL(apiURL, orgID, format),
		bytes.NewBuffer([]byte(fmt.Sprintf(`{"depGraph":%s}`, depGraph))),
	)
	if err != nil {
		return nil, extension_errors.NewInternalError(fmt.Errorf("error while creating request: %w", err))
	}
	req.Header.Add("Content-Type", MimeTypeJSON)

	logger.Printf("Converting depgraph remotely (url: %s)", req.URL.String())

	resp, err := client.Do(req)
	if err != nil {
		return nil, extension_errors.NewInternalError(fmt.Errorf("error while making request: %w", err))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errorFromResponse(resp, orgID)
	}

	defer resp.Body.Close()
	doc, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read response body: %w", err)
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
		return extension_errors.New(
			err,
			"SBOM generation failed due to bad input arguments. "+
				"Please make sure you are using the latest version of the Snyk CLI.",
		)
	case http.StatusUnauthorized:
		return extension_errors.New(
			err,
			"Snyk failed to authenticate you based on on you API token. "+
				"Please ensure that you have authenticated by running `snyk auth`.",
		)
	case http.StatusForbidden:
		return extension_errors.New(
			err,
			fmt.Sprintf(
				"Your account is not authorized to perform this action. "+
					"Please ensure that you belong to the given organization and that "+
					"the organization is entitled to use the Snyk API. (Org ID: %s)",
				orgID,
			),
		)
	default:
		return extension_errors.NewRemoteError(err)
	}
}

func ValidateSBOMFormat(candidate string) error {
	if candidate == "" {
		return extension_errors.New(
			fmt.Errorf("no format provided"),
			fmt.Sprintf(
				"Must set `--format` flag to specify an SBOM format. "+
					"Available formats are: %s",
				strings.Join(sbomFormats[:], ", "),
			),
		)
	}

	for _, f := range sbomFormats {
		if f == candidate {
			return nil
		}
	}

	return extension_errors.New(
		fmt.Errorf("invalid format provided (%s)", candidate),
		fmt.Sprintf(
			"The format provided (%s) is not one of the available formats. "+
				"Available formats are: %s",
			candidate,
			strings.Join(sbomFormats[:], ", "),
		),
	)
}
