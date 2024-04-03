//nolint:tagliatelle // Disabling for snake-case in JSON payloads.
package sbomtest

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

type presenterFormat int

const (
	PresenterFormatPretty presenterFormat = iota
	PresenterFormatJSON

	MIMETypeJSON = "application/json"
	MIMETypeText = "text/plain"
)

type Presenter struct {
	Format presenterFormat
}

func newPresenter(ictx workflow.InvocationContext) *Presenter {
	f := PresenterFormatPretty

	if ictx.GetConfiguration().GetBool("json") {
		f = PresenterFormatJSON
	}

	return &Presenter{
		Format: f,
	}
}

// TODO: this is just a temporary type def which should get replaced
// with a definition from the SBOM Test Client.
type TestResult struct {
	Summary TestSummary `json:"summary"`
}
type TestSummary struct {
	TotalVulnerabilities int `json:"total_vulnerabilities"`
}

func (p Presenter) Render(result TestResult) (data []byte, contentType string, err error) {
	switch p.Format {
	default:
		return nil, "", errors.New("presenter has no format")
	case PresenterFormatJSON:
		return renderJSONResult(result)
	case PresenterFormatPretty:
		return renderPrettyResult(result)
	}
}

func renderJSONResult(result TestResult) (data []byte, contentType string, err error) {
	contentType = MIMETypeJSON

	data, err = json.Marshal(result)
	if err != nil {
		return nil, contentType, err
	}

	return data, contentType, nil
}

func renderPrettyResult(result TestResult) (data []byte, contentType string, err error) {
	// TODO: this is a mock template. Should get replaced.
	tpl := `TEST RESULTS
------------
❌ Found a total of %d vulnerabilities
`

	return []byte(fmt.Sprintf(tpl, result.Summary.TotalVulnerabilities)), MIMETypeText, nil
}
