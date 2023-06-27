package depgraph //nolint:testpackage // we want to use private functions.

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/snyk/cli-extension-sbom/pkg/flag"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Depgraph_extractLegacyCLIError_extractError(t *testing.T) {
	expectedMsgJson := `{
		"ok": false,
		"error": "Hello Error",
		"path": "/"
	  }`

	inputError := &exec.ExitError{}
	data := workflow.NewData(noOpWorkflow.TypeIdentifier(), "application/json", []byte(expectedMsgJson))

	outputError := extractLegacyCLIError(inputError, []workflow.Data{data})

	assert.NotNil(t, outputError)
	assert.Equal(t, "Hello Error", outputError.Error())

	var legacyErr *legacyCLIJSONError
	assert.ErrorAs(t, outputError, &legacyErr)
}

func Test_Depgraph_extractLegacyCLIError_InputSameAsOutput(t *testing.T) {
	inputError := fmt.Errorf("some other error")
	data := workflow.NewData(noOpWorkflow.TypeIdentifier(), "application/json", []byte{})

	outputError := extractLegacyCLIError(inputError, []workflow.Data{data})

	assert.NotNil(t, outputError)
	assert.Equal(t, inputError.Error(), outputError.Error())
}

func Test_Depgraph_InitDepGraphWorkflow(t *testing.T) {
	config := configuration.New()
	engine := workflow.NewWorkFlowEngine(config)

	err := noOpWorkflow.init(engine)
	assert.Nil(t, err)

	flagBool := config.Get("flag-bool")
	assert.Equal(t, false, flagBool)

	flagString := config.Get("flag-string")
	assert.Equal(t, "", flagString)
}

func TestExtractDepGraphsFromCLIOutput(t *testing.T) {
	type depGraph struct {
		name string
		file string
	}
	type testCase struct {
		cliOutputFile string
		graphs        []depGraph
	}

	testCases := []testCase{{
		cliOutputFile: "testdata/single_depgraph_output.txt",
		graphs: []depGraph{{
			name: "package-lock.json",
			file: "testdata/single_depgraph.json",
		}},
	}, {
		cliOutputFile: "testdata/multi_depgraph_output.txt",
		graphs: []depGraph{{
			name: "docker-image|snyk/kubernetes-scanner",
			file: "testdata/multi_depgraph_1.json",
		}, {
			name: "docker-image|snyk/kubernetes-scanner:/kubernetes-scanner",
			file: "testdata/multi_depgraph_2.json",
		}},
	}}

	d := Workflow[*noOpConfig]{
		Name:   "whatever",
		Config: Config[*noOpConfig]{},
	}

	for _, tc := range testCases {
		t.Run(tc.cliOutputFile, func(t *testing.T) {
			output, err := os.ReadFile(tc.cliOutputFile)
			require.NoError(t, err)

			data, err := d.extractDepGraphsFromCLIOutput(output)
			require.NoError(t, err)

			require.Len(t, data, len(tc.graphs))
			var i int
			for _, graph := range tc.graphs {
				testDepGraphFromFile(t, graph.name, graph.file, data[i])
				i++
			}
		})
	}
}

var noOpWorkflow = NewWorkflow[noOpConfig]("noop", noOpConfig{})

type noOpConfig struct{}

func (n noOpConfig) Command() []string {
	return []string{"hello"}
}
func (n noOpConfig) Flags() flag.Flags {
	return flag.Flags{
		flag.Flag[bool]{Name: "flag-bool"},
		flag.Flag[string]{Name: "flag-string"},
	}
}

func testDepGraphFromFile(t *testing.T, dgName, fileName string, actual workflow.Data) {
	t.Helper()
	content, err := os.ReadFile(fileName)
	require.NoError(t, err)

	var expectedDG map[string]interface{}
	err = json.Unmarshal(content, &expectedDG)
	require.NoError(t, err)

	require.Equal(t, depGraphContentType, actual.GetContentType())
	require.Equal(t, dgName, actual.GetContentLocation())

	payload, ok := actual.GetPayload().([]byte)
	if !ok {
		t.Fatalf("payload is not []byte: %T", actual.GetPayload())
	}

	var actualDG map[string]interface{}
	err = json.Unmarshal(payload, &actualDG)
	require.NoError(t, err)
	require.Equal(t, expectedDG, actualDG)
}
