package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking"
)

type SBOMFormat string

const (
	apiVersion            = "2022-03-31~experimental"
	MimeTypeCycloneDXJSON = "application/vnd.cyclonedx+json"
	MimeTypeJSON          = "application/json"

	SBOMFormatCycloneDXJSON SBOMFormat = "cyclonedx+json"
)

func DepGraphToSBOM(
	cfg configuration.Configuration,
	depGraph []byte,
	format SBOMFormat,
) (docs []byte, err error) {
	orgID := cfg.GetString(configuration.ORGANIZATION)
	apiURL := cfg.GetString(configuration.API_URL)

	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		buildURL(apiURL, orgID, format),
		bytes.NewBuffer([]byte(fmt.Sprintf(`{"depGraph":%s}`, depGraph))),
	)
	if err != nil {
		return nil, fmt.Errorf("error while creating request: %w", err)
	}
	req.Header.Add("Content-Type", MimeTypeJSON)

	resp, err := networking.
		NewNetworkAccess(cfg).
		GetHttpClient().
		Do(req)
	if err != nil {
		return nil, fmt.Errorf("error while making request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("could not convert to SBOM (status: %s)", resp.Status)
	}

	if resp.Header.Get("Content-Type") != MimeTypeCycloneDXJSON {
		return nil, errors.New("received unexpected response format")
	}

	defer resp.Body.Close()
	docs, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read response body: %w", err)
	}

	return docs, nil
}

func buildURL(apiURL, orgID string, format SBOMFormat) string {
	return fmt.Sprintf(
		"%s/hidden/orgs/%s/sbom?version=%s&format=%s",
		apiURL, orgID, apiVersion, url.QueryEscape(string(format)),
	)
}
