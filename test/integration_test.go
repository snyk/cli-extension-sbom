package test //nolint:testpackage // we want to use currently private functions in the test package.

import (
	_ "embed"
	"strings"
	"testing"

	osdepgraph "github.com/snyk/cli-extension-sbom/internal/opensource/depgraph"
	ossbom "github.com/snyk/cli-extension-sbom/internal/opensource/sbom"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

var (
	//go:embed testdata/opensource_scan_output.txt
	openSourceScanOutput []byte
	//go:embed testdata/opensource_scan_depgraph.json
	openSourceDepGraph []byte
)

func TestIntegration(t *testing.T) {
	const orgID = "whatever-org-id"
	fakeSBOMDoc := []byte("this is an sbom document")

	testServer := MockSBOMService(Response{Body: fakeSBOMDoc},
		AssertJSONBody(t, strings.TrimSpace(string(openSourceDepGraph))),
		AssertSBOMURLPath(t, orgID),
	)
	t.Cleanup(testServer.Close)

	// we're not re-using constants / variables for these names to ensure they match our
	// expectations as well.
	config := map[string]any{
		"format":              "cyclonedx1.4+json",
		"org":                 orgID,
		configuration.API_URL: testServer.URL,
		// doesn't matter much.
		"targetDirectory": "./testdata/container_scan_output.txt",
	}

	if err := RunCommand("sbom", config, fakeSBOMDoc,
		osdepgraph.InitWorkflow,
		ossbom.InitWorkflow,
		LegacyCLI(openSourceScanOutput),
	); err != nil {
		t.Fatalf("%v", err)
	}
}
