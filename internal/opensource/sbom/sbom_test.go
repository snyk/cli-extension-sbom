package sbom //nolint:testpackage // we want to test private fields & functions.

import (
	_ "embed"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"

	osdepgraph "github.com/snyk/cli-extension-sbom/internal/opensource/depgraph"
	"github.com/snyk/cli-extension-sbom/test"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	openSourceDepGraphID = osdepgraph.Workflow.Identifier()
)

//go:embed testdata/cyclonedx_document.json
var expectedSBOM []byte

//go:embed testdata/depgraph.json
var depGraphData []byte

func TestInit(t *testing.T) {
	c := configuration.New()
	e := workflow.NewWorkFlowEngine(c)

	err := e.Init()
	assert.NoError(t, err)

	err = InitWorkflow(e)
	assert.NoError(t, err)

	wflw, ok := e.GetWorkflow(Workflow.Identifier())
	assert.True(t, ok)
	assert.NotNil(t, wflw)
}

func TestSBOMWorkflow_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockResponse := test.Response{ContentType: "application/vnd.cyclonedx+json", Body: expectedSBOM}
	mockSBOMService := test.MockSBOMService(mockResponse)
	defer mockSBOMService.Close()
	mockICTX := mockInvocationContext(t, ctrl, mockSBOMService.URL, nil, openSourceDepGraphID)

	results, err := Workflow.Entrypoint(mockICTX, []workflow.Data{})
	assert.NoError(t, err)
	assert.Len(t, results, 1)
	assert.NotNil(t, results[0])
	sbomBytes, ok := results[0].GetPayload().([]byte)
	assert.True(t, ok)
	assert.Equal(t, string(expectedSBOM), string(sbomBytes))
}

func TestSBOMWorkflow_EmptyFormat(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockICTX := mockInvocationContext(t, ctrl, "", nil, openSourceDepGraphID)
	mockICTX.GetConfiguration().Set("format", "")

	_, err := Workflow.Entrypoint(mockICTX, []workflow.Data{})

	assert.ErrorContains(t, err, "Must set `--format` flag to specify an SBOM format.")
}

func TestSBOMWorkflow_InvalidFormat(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockICTX := mockInvocationContext(t, ctrl, "", nil, openSourceDepGraphID)
	mockICTX.GetConfiguration().Set("format", "cyclonedx+json")

	_, err := Workflow.Entrypoint(mockICTX, []workflow.Data{})

	assert.ErrorContains(t, err, "The format provided (cyclonedx+json) is not one of the available formats. "+
		"Available formats are: cyclonedx1.4+json, cyclonedx1.4+xml, spdx2.3+json")
}

func TestSBOMWorkflow_NoOrgID(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockICTX := mockInvocationContext(t, ctrl, "", nil, openSourceDepGraphID)
	mockICTX.GetConfiguration().Set(configuration.ORGANIZATION, "")

	_, err := Workflow.Entrypoint(mockICTX, []workflow.Data{})

	assert.ErrorContains(t, err, "Snyk failed to infer an organization ID. Please make sure to authenticate using `snyk auth`. "+
		"Should the issue persist, explicitly set an organization ID via the `--org` flag.")
}

func TestSBOMWorkflow_InvalidPayload(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockEngine := newMockEngine(
		ctrl,
		// TODO: cleanup...
		[]workflow.Data{workflow.NewData(workflow.NewTypeIdentifier(openSourceDepGraphID, "cyclonedx"), "application/json", nil)},
		openSourceDepGraphID,
		nil,
	)
	mockICTX := mockInvocationContext(t, ctrl, "", mockEngine, openSourceDepGraphID)

	_, err := Workflow.Entrypoint(mockICTX, nil)

	assert.ErrorContains(t, err, "An error occurred while running the underlying analysis which is required to generate the SBOM. "+
		"Should this issue persist, please reach out to customer support.")
}

func TestSBOMWorkflow_DepGraphError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockEngine := newMockEngine(ctrl, nil,
		openSourceDepGraphID,
		errors.New("error during composition analysis"),
	)
	mockICTX := mockInvocationContext(t, ctrl, "", mockEngine, openSourceDepGraphID)

	_, err := Workflow.Entrypoint(mockICTX, []workflow.Data{})

	assert.ErrorContains(t, err, "An error occurred while running the underlying analysis needed to generate the SBOM.")
}

func TestSBOMWorkflow_MultipleDepGraphs(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockResponse := test.Response{ContentType: "application/vnd.cyclonedx+json", Body: []byte("{}")}
	mockSBOMService := test.MockSBOMService(mockResponse,
		test.AssertJSONBody(t, `{"depGraphs":[{"pkgManager":{"name":"npm"}},{"pkgManager":{"name":"nuget"}}],"subject":{"name":"goof","version":"0.0.0"}}`),
	)
	defer mockSBOMService.Close()
	mockEngine := newMockEngine(ctrl, []workflow.Data{
		newDepGraphData(t, []byte(`{"pkgManager":{"name":"npm"}}`)),
		newDepGraphData(t, []byte(`{"pkgManager":{"name":"nuget"}}`)),
	}, openSourceDepGraphID, nil)
	mockICTX := mockInvocationContext(t, ctrl, mockSBOMService.URL, mockEngine, openSourceDepGraphID)

	results, err := Workflow.Entrypoint(mockICTX, []workflow.Data{})

	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.NotNil(t, results[0])
	sbomBytes, ok := results[0].GetPayload().([]byte)
	assert.True(t, ok)
	assert.JSONEq(t, "{}", string(sbomBytes))
}

func TestSBOMWorkflow_MergeSubject(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockResponse := test.Response{ContentType: "application/vnd.cyclonedx+json", Body: []byte("{}")}
	mockSBOMService := test.MockSBOMService(mockResponse,
		test.AssertJSONBody(t, `{"depGraphs":[{},{}],"subject":{"name":"sbom","version":""}}`),
	)
	defer mockSBOMService.Close()
	mockEngine := newMockEngine(ctrl,
		[]workflow.Data{newDepGraphData(t, []byte(`{}`)), newDepGraphData(t, []byte(`{}`))},
		openSourceDepGraphID, nil,
	)
	mockICTX := mockInvocationContext(t, ctrl, mockSBOMService.URL, mockEngine, openSourceDepGraphID)
	mockICTX.GetConfiguration().Set("name", "")
	mockICTX.GetConfiguration().Set("version", "")

	_, err := Workflow.Entrypoint(mockICTX, []workflow.Data{})
	require.NoError(t, err)
}

func mockInvocationContext(
	t *testing.T,
	ctrl *gomock.Controller,
	sbomServiceURL string,
	mockEngine *mocks.MockEngine,
	id workflow.Identifier,
) workflow.InvocationContext {
	t.Helper()

	mockLogger := log.New(io.Discard, "", 0)

	mockConfig := configuration.New()
	mockConfig.Set(configuration.AUTHENTICATION_TOKEN, "<SOME API TOKEN>")
	mockConfig.Set(configuration.ORGANIZATION, "6277734c-fc84-4c74-9662-33d46ec66c53")
	mockConfig.Set(configuration.API_URL, sbomServiceURL)
	mockConfig.Set("format", "cyclonedx1.4+json")
	mockConfig.Set("name", "goof")
	mockConfig.Set("version", "0.0.0")

	if mockEngine == nil {
		mockEngine = newMockEngine(
			ctrl,
			[]workflow.Data{newDepGraphData(t, depGraphData)},
			id,
			nil,
		)
	}

	ictx := mocks.NewMockInvocationContext(ctrl)
	ictx.EXPECT().GetConfiguration().Return(mockConfig).AnyTimes()
	ictx.EXPECT().GetEngine().Return(mockEngine).AnyTimes()
	ictx.EXPECT().GetNetworkAccess().Return(networking.NewNetworkAccess(mockConfig)).AnyTimes()
	ictx.EXPECT().GetLogger().Return(mockLogger).AnyTimes()

	return ictx
}

func newMockEngine(ctrl *gomock.Controller, result []workflow.Data, id workflow.Identifier, err error) *mocks.MockEngine {
	mockEngine := mocks.NewMockEngine(ctrl)

	mockEngine.
		EXPECT().
		InvokeWithConfig(gomock.Eq(id), gomock.Any()).
		Return(result, err).
		AnyTimes()

	return mockEngine
}

func newDepGraphData(t *testing.T, bts []byte) workflow.Data {
	t.Helper()

	return workflow.NewData(
		workflow.NewTypeIdentifier(openSourceDepGraphID, "cyclonedx"),
		"application/json",
		bts,
	)
}

func TestWorkflowInvokeSetsFlags(t *testing.T) {
	dg := depGraph()
	config := configuration.New()
	engine := workflow.NewWorkFlowEngine(config)
	fs := pflag.NewFlagSet(dg.Name, pflag.PanicOnError)

	_, err := engine.Register(
		dg.Identifier(),
		workflow.ConfigurationOptionsFromFlagset(fs),
		func(invocation workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
			if !invocation.GetConfiguration().GetBool(dg.SubCommand.FailFast.Name) {
				return nil, fmt.Errorf("fail-fast is not set, but expected it to be!")
			}
			return nil, nil
		})
	if err != nil {
		t.Fatalf("error registering depgraph workflow: %v", err)
	}
	if err := engine.Init(); err != nil {
		t.Fatalf("error initializing workflow engine: %v", err)
	}

	config.Set(dg.SubCommand.AllProjects.Name, true)

	if _, err := dg.Invoke(engine, config); err != nil {
		t.Errorf("did not expect error from invoke, but got %v", err)
	}
}

func TestWorkflowMetadata(t *testing.T) {
	wd, err := os.Getwd()
	require.NoError(t, err)
	wd = filepath.Base(wd)

	type testCases struct {
		config    map[string]any
		workflows int
		name      string
		version   string
	}
	tcs := map[string]testCases{
		"fallback to working dir": {
			config:    map[string]any{},
			workflows: 2,
			name:      wd,
			version:   "",
		},
		"ignore flag values if not multiple depgraphs": {
			config: map[string]any{
				// we're not re-using the typed fields of the workflow, where we could access these
				// flag names, to ensure our assumptions are correct as well and that we didn't typo
				// the flag name.
				"name":    "foo",
				"version": "v1.0.0",
			},
			workflows: 1,
			name:      "",
			version:   "",
		},
		"use flags for multiple depgraphs": {
			config: map[string]any{
				"name": "foo",
			},
			workflows: 2,
			name:      "foo",
			version:   "",
		},
		"honor version flag": {
			config: map[string]any{
				"name":    "foo",
				"version": "v1.0.0",
			},
			workflows: 2,
			name:      "foo",
			version:   "v1.0.0",
		},
		"fallback to working dir even if version is specified": {
			config: map[string]any{
				"version": "v1.0.0",
			},
			workflows: 2,
			name:      wd,
			version:   "v1.0.0",
		},
	}
	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			config := configuration.New()
			for k, v := range tc.config {
				config.Set(k, v)
			}

			data := make([]workflow.Data, tc.workflows)
			name, version, err := depGraph().Metadata(config, data)
			if err != nil {
				t.Fatalf("did not expect error, but got %v", err)
			}
			if name != tc.name {
				t.Fatalf("name does not match. expected=%q, got=%q", tc.name, name)
			}
			if version != tc.version {
				t.Fatalf("version does not match. expected=%q, got=%q", tc.version, version)
			}
		})
	}
}
