package sbom //nolint:testpackage // we want to test private fields & functions.

import (
	_ "embed"
	"io"
	"net/http"
	"testing"

	"github.com/snyk/cli-extension-sbom/internal/mocks"
	"github.com/snyk/cli-extension-sbom/pkg/flag"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewWorkflowInit(t *testing.T) {
	c := configuration.New()
	e := workflow.NewWorkFlowEngine(c)

	if err := e.Init(); err != nil {
		t.Fatalf("error initializing engine: %v", err)
	}

	w := NewWorkflow("my sbom", mockDepGrapher{})
	if err := InitWorkflow(e, w); err != nil {
		t.Fatalf("could not initialize workflow: %v", err)
	}

	_, ok := e.GetWorkflow(workflow.NewWorkflowIdentifier("my sbom"))
	if !ok {
		t.Fatalf("expected to get ok, but did not")
	}
	flags := w.Flags()
	if len(flags) != 1 {
		t.Fatalf("wrong amount of flags. expected=%v, got=%v", 1, len(flags))
	}
	if flags[0] != w.format {
		t.Fatalf("expected only flag to be format flag, but got %+v", flags[0])
	}
}

func TestWorkflowEntrypoint(t *testing.T) {
	type testCase struct {
		depGraphs         [][]byte
		dgName, dgVersion string
		expectedRequest   string
	}
	tcs := map[string]testCase{
		"single graph": {
			depGraphs: [][]byte{
				[]byte(`{}`),
			},
			expectedRequest: `{"depGraph":{}}`,
		},
		"multiple graphs": {
			depGraphs: [][]byte{
				[]byte(`{"foo": true}`),
				[]byte(`{"bar": true}`),
			},
			dgName:          "baz",
			dgVersion:       "v1.0.0",
			expectedRequest: `{"depGraphs":[{"foo":true},{"bar":true}],"subject":{"name":"baz","version":"v1.0.0"}}`,
		},
	}
	const orgID = "abc"
	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			c := configuration.New()
			e := workflow.NewWorkFlowEngine(c)

			if err := e.Init(); err != nil {
				t.Fatalf("error initializing engine: %v", err)
			}

			w := NewWorkflow("my sbom", mockDepGrapher{
				depGraphs: tc.depGraphs,
				name:      tc.dgName,
				version:   tc.dgVersion,
			})
			if err := InitWorkflow(e, w); err != nil {
				t.Fatalf("could not initialize workflow: %v", err)
			}

			response := mocks.NewMockResponse("", nil, http.StatusOK)
			ts := mocks.NewMockSBOMService(response, func(r *http.Request) {
				body, err := io.ReadAll(r.Body)
				defer r.Body.Close()
				require.NoError(t, err)
				assert.JSONEq(t, tc.expectedRequest, string(body))
			})
			t.Cleanup(ts.Close)

			c.Set(configuration.ORGANIZATION, orgID)
			c.Set("format", "cyclonedx1.4+json")
			c.Set(configuration.API_URL, ts.URL)

			_, err := e.InvokeWithConfig(w.Identifier(), c)
			if err != nil {
				t.Fatalf("did not expect error, but got: %v", err)
			}
		})
	}
}

func TestWorkflowConfigErrors(t *testing.T) {
	invalidConfigs := []map[string]any{{
		"format": "not-a-valid-format",
	}, {
		"format":                   "cyclonedx1.4+json",
		configuration.ORGANIZATION: "",
	}}
	for _, config := range invalidConfigs {
		c := configuration.New()
		e := workflow.NewWorkFlowEngine(c)

		if err := e.Init(); err != nil {
			t.Fatalf("error initializing engine: %v", err)
		}

		w := NewWorkflow("my sbom", mockDepGrapher{})
		if err := InitWorkflow(e, w); err != nil {
			t.Fatalf("could not initialize workflow: %v", err)
		}
		for k, v := range config {
			c.Set(k, v)
		}
		_, err := e.InvokeWithConfig(w.Identifier(), c)
		if err == nil {
			t.Fatalf("expected error, but got none")
		}
	}
}

type mockDepGrapher struct {
	depGraphs     [][]byte
	name, version string
}

func (n mockDepGrapher) Metadata(_ configuration.Configuration, _ []workflow.Data) (name, version string, err error) {
	return n.name, n.version, nil
}

func (n mockDepGrapher) Invoke(workflow.Engine, configuration.Configuration) ([]workflow.Data, error) {
	typeID := workflow.NewTypeIdentifier(
		workflow.NewWorkflowIdentifier("depgraph"),
		"depgraph",
	)
	datas := make([]workflow.Data, 0, len(n.depGraphs))
	for _, dg := range n.depGraphs {
		data := workflow.NewData(typeID, "application/json", dg)
		data.SetMetaData("Content-Location", "whatever")
		datas = append(datas, data)
	}
	return datas, nil
}
func (mockDepGrapher) Flags() flag.Flags { return nil }
