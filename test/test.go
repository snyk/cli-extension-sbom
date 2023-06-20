package test

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

// RunCommand runs the given command against the CLI engine, using the specified configValues to
// invoke it. Will match the output of that executed command to the given expectedOutput. The
// commands that will be invoked need to be registered and thus supplied through the commands param.
func RunCommand(command string, configValues map[string]any, expectedOutput []byte, commands ...workflow.ExtensionInit) error {
	config := configuration.New()
	e := workflow.NewWorkFlowEngine(config)

	for _, cmd := range commands {
		e.AddExtensionInitializer(cmd)
	}

	if err := e.Init(); err != nil {
		return fmt.Errorf("error initializing engine: %w", err)
	}

	for k, v := range configValues {
		config.Set(k, v)
	}

	d, err := e.InvokeWithConfig(workflow.NewWorkflowIdentifier(command), config)
	if err != nil {
		return fmt.Errorf("error invoking command %q: %w", command, err)
	}

	if len(d) != 1 {
		return fmt.Errorf("wrong amount of data: expected=%v, got=%v", 1, len(d))
	}

	body, ok := d[0].GetPayload().([]byte)
	if !ok {
		return fmt.Errorf("payload has wrong type. expected=[]byte, got=%T", d[0].GetPayload())
	}

	if !bytes.Equal(body, expectedOutput) {
		return fmt.Errorf("bytes not equal. expected=%s, got=%s", expectedOutput, body)
	}
	return nil
}

// legacyCLI is a mock for the "legacy CLI" (e.g. the TypeScript parts) and simply returns the given
// output slice as data.
func LegacyCLI(output []byte) workflow.ExtensionInit {
	return func(e workflow.Engine) error {
		id := workflow.NewWorkflowIdentifier("legacycli")
		_, err := e.Register(
			id,
			workflow.ConfigurationOptionsFromFlagset(pflag.NewFlagSet("snyk", pflag.ExitOnError)),
			func(invocation workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
				return []workflow.Data{
					workflow.NewData(workflow.NewTypeIdentifier(id, "snyk"), "application/json", output),
				}, nil
			})
		return err
	}
}

type Response struct {
	// ContentType for the response ("Content-Type" Header), optional.
	ContentType string
	// Body of the response, optional.
	Body []byte
	// Status code for the response, optional. defaults to 200.
	Status int
}

func AssertSBOMURLPath(t *testing.T, expectedOrgID string) func(r *http.Request) {
	t.Helper()
	return func(r *http.Request) {
		expectedPath := "/hidden/orgs/" + expectedOrgID + "/sbom"
		assert.Equal(t, expectedPath, r.URL.Path)
	}
}

func AssertJSONBody(t *testing.T, expectedJSON string) func(*http.Request) {
	t.Helper()
	return func(r *http.Request) {
		defer r.Body.Close()
		b, err := io.ReadAll(r.Body)
		assert.NoError(t, err)

		assert.JSONEq(t, expectedJSON, string(b))
	}
}

func MockSBOMService(resp Response, assertions ...func(r *http.Request)) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, assert := range assertions {
			assert(r)
		}

		if resp.ContentType != "" {
			w.Header().Set("Content-Type", resp.ContentType)
		}
		if resp.Status == 0 {
			resp.Status = http.StatusOK
		}
		w.WriteHeader(resp.Status)

		if resp.Body != nil {
			if _, err := w.Write(resp.Body); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
			}
		}
	}))

	return ts
}
