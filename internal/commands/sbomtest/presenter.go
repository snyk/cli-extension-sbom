package sbomtest

import (
	"errors"

	"github.com/snyk/go-application-framework/pkg/workflow"
	"golang.org/x/exp/slices"

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

func newPresenter(ictx workflow.InvocationContext) *Presenter {
	f := PresenterFormatPretty

	if ictx.GetConfiguration().GetBool("json") {
		f = PresenterFormatJSON
	}

	return &Presenter{
		format: f,
	}
}

func (p Presenter) Render(file string, result *snykclient.GetSBOMTestResultResponseBody, printDeps bool) (data []byte, contentType string, err error) {
	switch p.format {
	default:
		return nil, "", errors.New("presenter has no format")
	case PresenterFormatJSON:
		return asJSON(result)
	case PresenterFormatPretty:
		return renderPrettyResult(file, result, printDeps)
	}
}

func SortVulns(vulns map[string]snykclient.VulnerabilityResource) []snykclient.VulnerabilityResource {
	result := make([]snykclient.VulnerabilityResource, 0, len(vulns))

	for id := range vulns {
		result = append(result, vulns[id])
	}

	slices.SortFunc(result, func(a, b snykclient.VulnerabilityResource) int {
		if a.SeverityLevel != b.SeverityLevel {
			return int(a.SeverityLevel - b.SeverityLevel)
		}

		if a.ID < b.ID {
			return -1
		}

		if a.ID > b.ID {
			return +1
		}

		return 0
	})

	return result
}
