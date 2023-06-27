package depgraph_test

import (
	"log"
	"os"
	"testing"

	"github.com/snyk/cli-extension-sbom/internal/opensource/depgraph"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Depgraph_InitDepGraphWorkflow(t *testing.T) {
	config := configuration.New()
	engine := workflow.NewWorkFlowEngine(config)

	err := depgraph.InitWorkflow(engine)
	assert.Nil(t, err)

	allProjects := config.Get("all-projects")
	assert.Equal(t, false, allProjects)

	inputFile := config.Get("file")
	assert.Equal(t, "", inputFile)
}

var legacyCLIID = workflow.NewWorkflowIdentifier("legacycli")

func TestLegacyCLIInvocation(t *testing.T) {
	logger := log.New(os.Stderr, "test", 0)
	ctrl := gomock.NewController(t)

	config := configuration.New()
	engineMock := mocks.NewMockEngine(ctrl)
	invocationContextMock := mocks.NewMockInvocationContext(ctrl)
	config.Set("targetDirectory", ".")

	// invocation context mocks
	invocationContextMock.EXPECT().GetEngine().Return(engineMock).AnyTimes()
	invocationContextMock.EXPECT().GetLogger().Return(logger).AnyTimes()
	invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
	dataIdentifier := depgraph.Workflow.TypeIdentifier()
	data := workflow.NewData(dataIdentifier, "application/json", []byte(nil))

	// engine mocks
	engineMock.EXPECT().InvokeWithConfig(legacyCLIID, config).Return([]workflow.Data{data}, nil).Times(1)

	// execute
	// we always expect an error because we don't return a depGraph from the legacycli call.
	_, err := depgraph.Workflow.Entrypoint(invocationContextMock, []workflow.Data{})
	require.NotNil(t, err)

	assert.Equal(t,
		[]string{"test", "--print-graph", "--json", "."},
		config.Get(configuration.RAW_CMD_ARGS),
	)
}

func TestDepGraphArgs(t *testing.T) {
	logger := log.New(os.Stderr, "test", 0)
	ctrl := gomock.NewController(t)

	c := depgraph.Workflow.Config
	type testCase struct {
		arg      string
		value    interface{}
		expected string
	}
	testCases := []testCase{{
		arg:      c.Debug.Name,
		expected: "--debug",
		value:    true,
	}, {
		arg:      c.SubCommand.AllProjects.Name,
		expected: "--all-projects",
		value:    true,
	}, {
		arg:      c.SubCommand.Dev.Name,
		expected: "--dev",
		value:    true,
	}, {
		arg:      c.SubCommand.FailFast.Name,
		expected: "--fail-fast",
		value:    true,
	}, {
		arg:      c.SubCommand.File.Name,
		expected: "--file=path/to/target/file.js",
		value:    "path/to/target/file.js",
	}, {
		arg:      c.SubCommand.Exclude.Name,
		expected: "--exclude=path/to/target/file.js",
		value:    "path/to/target/file.js",
	}, {
		arg:      c.SubCommand.DetectionDepth.Name,
		expected: "--detection-depth=42",
		value:    "42",
	}, {
		arg:      c.SubCommand.PruneRepeatedSubdependencies.Name,
		expected: "--prune-repeated-subdependencies",
		value:    true,
	}, {
		arg:      "targetDirectory",
		expected: "path/to/target",
		value:    "path/to/target",
	}}

	for _, tc := range testCases {
		t.Run("test flag "+tc.arg, func(t *testing.T) {
			// setup a clean slate for every test.
			config := configuration.New()
			engineMock := mocks.NewMockEngine(ctrl)
			invocationContextMock := mocks.NewMockInvocationContext(ctrl)

			// invocation context mocks
			invocationContextMock.EXPECT().GetEngine().Return(engineMock).AnyTimes()
			invocationContextMock.EXPECT().GetLogger().Return(logger).AnyTimes()
			invocationContextMock.EXPECT().GetConfiguration().Return(config).AnyTimes()
			config.Set(tc.arg, tc.value)
			dataIdentifier := depgraph.Workflow.TypeIdentifier()
			data := workflow.NewData(dataIdentifier, "application/json", []byte(nil))

			// engine mocks
			engineMock.EXPECT().InvokeWithConfig(legacyCLIID, config).Return([]workflow.Data{data}, nil).Times(1)

			// execute
			// we always expect an error because we don't return a depGraph from the legacycli call.
			_, err := depgraph.Workflow.Entrypoint(invocationContextMock, []workflow.Data{})
			require.Error(t, err)

			commandArgs := config.Get(configuration.RAW_CMD_ARGS)
			assert.Contains(t, commandArgs, tc.expected)
		})
	}
}
