package service

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
)

type SBOMResult struct {
	Doc      []byte
	MIMEType string
}

const (
	apiVersion   = "2022-03-31~experimental"
	MimeTypeJSON = "application/json"
)

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
		return nil, fmt.Errorf("error while creating request: %w", err)
	}
	req.Header.Add("Content-Type", MimeTypeJSON)

	logger.Printf("Converting depgraph remotely (url: %s)", req.URL.String())

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error while making request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("could not convert to SBOM (status: %s)", resp.Status)
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
