package sbomtest

import (
	"errors"

	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-sbom/internal/snykclient"
)

type presenterFormat int

const (
	PresenterFormatPretty presenterFormat = iota
	PresenterFormatJSON

	MIMETypeJSON = "application/json"
	MIMETypeText = "text/plain"
)

type Presenter struct {
	format presenterFormat
}

func NewPresenter(ictx workflow.InvocationContext) *Presenter {
	f := PresenterFormatPretty

	if ictx.GetConfiguration().GetBool("json") {
		f = PresenterFormatJSON
	}

	return &Presenter{
		format: f,
	}
}

func (p Presenter) Render(file string, body *snykclient.GetSBOMTestResultResponseBody, printDeps bool) (data []byte, contentType string, err error) {
	switch p.format {
	default:
		return nil, "", errors.New("presenter has no format")
	case PresenterFormatJSON:
		return asJSON(body)
	case PresenterFormatPretty:
		return renderPrettyResult(file, body, printDeps)
	}
}
