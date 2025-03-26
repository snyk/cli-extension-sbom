package snykclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"

	"github.com/snyk/cli-extension-sbom/internal/errors"
)

const (
	sbomConvertAPIVersion = "2025-03-06~beta"
)

func (t *SnykClient) SBOMConvert(
	ctx context.Context,
	errFactory *errors.ErrorFactory,
	sbom io.Reader,
) ([]*ScanResult, error) {
	u, err := buildSBOMConvertAPIURL(t.apiBaseURL, sbomConvertAPIVersion, t.orgID)
	if err != nil {
		return nil, errFactory.NewSCAError(err)
	}

	pipeReader, pipeWriter := io.Pipe()
	multipartWriter := multipart.NewWriter(pipeWriter)

	go func() {
		defer pipeWriter.Close()

		fileWriter, err := multipartWriter.CreateFormFile("sbom", "sbom_file") //nolint:govet // Shadowing err not an issue
		if err != nil {
			pipeWriter.CloseWithError(err)
			return
		}

		_, err = io.Copy(fileWriter, sbom)
		if err != nil {
			pipeWriter.CloseWithError(err)
			return
		}

		err = multipartWriter.Close()
		if err != nil {
			pipeWriter.CloseWithError(err)
			return
		}
	}()

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		u.String(),
		pipeReader,
	)
	if err != nil {
		return nil, errFactory.NewSCAError(err)
	}

	req.Header.Set(ContentTypeHeader, multipartWriter.FormDataContentType())

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, errFactory.NewSCAError(err)
	}
	defer resp.Body.Close()

	// TODO: when server-side things go wrong, we should be displaying a
	// request ID, interaction ID.

	if resp.StatusCode > 399 && resp.StatusCode < 500 {
		return nil, errFactory.NewSCAError(fmt.Errorf("request to analyze SBOM document was rejected: %s", resp.Status))
	}

	if resp.StatusCode > 499 {
		return nil, errFactory.NewSCAError(fmt.Errorf("analysis of SBOM document failed due to error: %s", resp.Status))
	}

	var convertResp SBOMConvertResponse
	err = json.NewDecoder(resp.Body).Decode(&convertResp)
	if err != nil {
		return nil, errFactory.NewSCAError(err)
	}

	return convertResp.ScanResults, nil
}

func buildSBOMConvertAPIURL(apiBaseURL, apiVersion, orgID string) (*url.URL, error) {
	u, err := url.Parse(apiBaseURL)
	if err != nil {
		return nil, err
	}

	u = u.JoinPath("hidden", "orgs", orgID, "sboms", "convert")

	query := url.Values{"version": {apiVersion}}
	u.RawQuery = query.Encode()

	return u, nil
}
