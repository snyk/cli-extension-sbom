package bundlestore

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	codeclient "github.com/snyk/code-client-go"
	codeclienthttp "github.com/snyk/code-client-go/http"
	codeclientscan "github.com/snyk/code-client-go/scan"
	"github.com/snyk/go-application-framework/pkg/configuration"

	listsources "github.com/snyk/cli-extension-sbom/internal/files"
)

type Client struct {
	httpClient *http.Client
	codeClientConfig
	codeScanner codeclient.CodeScanner
	logger      *zerolog.Logger
}

type (
	BundleFile struct {
		Hash    string `json:"hash"`
		Content string `json:"content"`
	}
	BundleResponse struct {
		BundleHash   string   `json:"bundleHash"`
		MissingFiles []string `json:"missingFiles"`
	}
	ExtendBundleRequest struct {
		Files        map[string]BundleFile `json:"files"`
		RemovedFiles []string              `json:"removedFiles,omitempty"`
	}
)

func NewClient(
	config configuration.Configuration,
	hc codeclienthttp.HTTPClientFactory,
	codeScannerMaybe *codeclient.CodeScanner, //nolint:gocritic // we want param to be optional
	logger *zerolog.Logger,
) *Client {
	codeScannerConfig := &codeClientConfig{
		localConfiguration: config,
	}

	httpClient := codeclienthttp.NewHTTPClient(
		hc,
		codeclienthttp.WithLogger(logger),
	)

	var codeScanner codeclient.CodeScanner
	if codeScannerMaybe != nil {
		codeScanner = *codeScannerMaybe
	} else {
		codeScanner = codeclient.NewCodeScanner(
			codeScannerConfig,
			httpClient,
			codeclient.WithLogger(logger),
		)
	}

	return &Client{
		hc(),
		*codeScannerConfig,
		codeScanner,
		logger,
	}
}

func (c *Client) request(
	ctx context.Context,
	method string,
	path string,
	requestBody []byte,
) ([]byte, error) {
	bodyBuffer, err := encodeRequestBody(requestBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, method, c.SnykCodeApi()+path, bodyBuffer)
	if err != nil {
		return nil, err
	}

	org := c.codeClientConfig.Organization()
	if org != "" {
		req.Header.Set("snyk-org-name", org)
	}
	// https://www.keycdn.com/blog/http-cache-headers
	req.Header.Set("Cache-Control", "private, max-age=0, no-cache")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Encoding", "gzip")

	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, fmt.Errorf("unexpected response code: %s (%s)", response.Status, response.Body)
	}

	defer func() {
		closeErr := response.Body.Close()
		if closeErr != nil {
			c.logger.Error().Err(closeErr).Msg("Couldn't close response body in call to Snyk Code")
		}
	}()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	return responseBody, nil
}

//nolint:gocritic // Code copied verbatim from go-application-framework
func (c *Client) createBundle(ctx context.Context, fileHashes map[string]string) (string, []string, error) {
	requestBody, err := json.Marshal(fileHashes)
	if err != nil {
		return "", nil, err
	}

	responseBody, err := c.request(ctx, http.MethodPost, "/bundle", requestBody)
	if err != nil {
		return "", nil, err
	}

	var bundle BundleResponse
	err = json.Unmarshal(responseBody, &bundle)
	if err != nil {
		return "", nil, err
	}
	return bundle.BundleHash, bundle.MissingFiles, nil
}

//nolint:gocritic // Code copied verbatim from go-application-framework
func (c *Client) extendBundle(ctx context.Context, bundleHash string, files map[string]BundleFile, removedFiles []string) (string, []string, error) {
	requestBody, err := json.Marshal(ExtendBundleRequest{
		Files:        files,
		RemovedFiles: removedFiles,
	})
	if err != nil {
		return "", nil, err
	}

	responseBody, err := c.request(ctx, http.MethodPut, "/bundle/"+bundleHash, requestBody)
	if err != nil {
		return "", nil, err
	}

	var bundleResponse BundleResponse
	err = json.Unmarshal(responseBody, &bundleResponse)
	if err != nil {
		return "", nil, err
	}
	return bundleResponse.BundleHash, bundleResponse.MissingFiles, err
}

func (c *Client) UploadSBOM(ctx context.Context, sbomPath string) (string, error) {
	var fileContent []byte
	fileContent, err := os.ReadFile(sbomPath)
	if err != nil {
		c.logger.Error().Err(err).Str("filePath", sbomPath).Msg("could not load content of file")
		return "", err
	}

	relativeFilePath, err := toRelativeUnixPath(filepath.Dir(sbomPath), sbomPath)
	if err != nil {
		return "", err
	}

	bf := bundleFileFrom(fileContent)
	fileHashes := make(map[string]string)
	fileHashes[relativeFilePath] = bf.Hash
	files := make(map[string]BundleFile)
	files[relativeFilePath] = bf

	bundleHash, _, err := c.createBundle(ctx, fileHashes)
	if err != nil {
		return "", err
	}
	bundleHash, missingFiles, err := c.extendBundle(ctx, bundleHash, files, []string{})
	if err != nil {
		return "", err
	}
	if len(missingFiles) > 0 {
		return "", fmt.Errorf("failed to create SBOM bundle")
	}
	return bundleHash, nil
}

func (c *Client) UploadSourceCode(ctx context.Context, sourceCodePath string) (string, error) {
	numThreads := runtime.NumCPU()
	filesChan, err := listsources.ListSourcesForPath(sourceCodePath, c.logger, numThreads)
	if err != nil {
		c.logger.Error().Err(err).Str("sourceCodePath", sourceCodePath).Msg("failed to list files in directory") //nolint:goconst // repeated sourceCodePath is fine
		return "", err
	}

	target, err := codeclientscan.NewRepositoryTarget(sourceCodePath)
	if err != nil {
		c.logger.Error().Err(err).Str("sourceCodePath", sourceCodePath).Msg("failed to initialize target")
		return "", err
	}

	requestID := uuid.New().String()
	bundle, err := c.codeScanner.Upload(ctx, requestID, target, filesChan, make(map[string]bool))
	if err != nil {
		c.logger.Error().Err(err).Str("sourceCodePath", sourceCodePath).Msg("failed to upload source code")
		return "", err
	}

	return bundle.GetBundleHash(), nil
}
