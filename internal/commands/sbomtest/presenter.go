package sbomtest

import (
	"errors"

	"github.com/snyk/cli-extension-sbom/internal/snykclient"
)

type presenterFormat int

const (
	FormatPretty presenterFormat = iota
	FormatJSON

	MIMETypeJSON = "application/json"
	MIMETypeText = "text/plain"
)

func Render(
	path string,
	body *snykclient.GetSBOMTestResultResponseBody,
	format presenterFormat,
	printDeps bool,
	org string,
) (data []byte, contentType string, err error) {
	switch format {
	default:
		return nil, "", errors.New("presenter has no format")
	case FormatJSON:
		return asJSON(body)
	case FormatPretty:
		return renderPrettyResult(path, body, printDeps, org)
	}
}
