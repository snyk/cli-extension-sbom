//nolint:goconst // is work in progress, should be improved soon.
package depgraph

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
)

var WORKFLOWID_DEPGRAPH_WORKFLOW workflow.Identifier = workflow.NewWorkflowIdentifier("depgraph")
var DATATYPEID_DEPGRAPH workflow.Identifier = workflow.NewTypeIdentifier(WORKFLOWID_DEPGRAPH_WORKFLOW, "depgraph")

// legacyCLIJSONError is the error type returned by the legacy cli.
type legacyCLIJSONError struct {
	Ok       bool   `json:"ok"`
	ErrorMsg string `json:"error"`
	Path     string `json:"path"`
}

// Error returns the LegacyCliJsonError error message.
func (e *legacyCLIJSONError) Error() string {
	return e.ErrorMsg
}

// extractLegacyCLIError extracts the error message from the legacy cli if possible.
func extractLegacyCLIError(input error, data []workflow.Data) (output error) {
	output = input

	// extract error from legacy cli if possible and wrap it in an error instance
	var exitErr *exec.ExitError
	if errors.As(input, &exitErr) && data != nil && len(data) > 0 {
		bytes, ok := data[0].GetPayload().([]byte)
		if !ok {
			return output
		}

		var decodedError legacyCLIJSONError
		err := json.Unmarshal(bytes, &decodedError)
		if err == nil {
			output = &decodedError
		}
	}

	return output
}

// InitDepGraphWorkflow initializes the depgraph workflow
// The depgraph workflow is responsible for handling the depgraph data
// As part of the localworkflows package, it is registered via the localworkflows.Init method.
func InitDepGraphWorkflow(engine workflow.Engine) error {
	depGraphConfig := pflag.NewFlagSet("depgraph", pflag.ExitOnError)
	depGraphConfig.Bool("fail-fast", false, "Fail fast when scanning all projects")
	depGraphConfig.Bool("all-projects", false, "Enable all projects")
	depGraphConfig.Bool("dev", false, "Include dev dependencies")
	depGraphConfig.String("file", "", "Input file")
	depGraphConfig.String("detection-depth", "", "Detection depth")
	depGraphConfig.BoolP("prune-repeated-subdependencies", "p", false, "Prune repeated sub-dependencies")

	_, err := engine.Register(WORKFLOWID_DEPGRAPH_WORKFLOW, workflow.ConfigurationOptionsFromFlagset(depGraphConfig), depgraphWorkflowEntryPoint)
	return err
}

// depgraphWorkflowEntryPoint defines the depgraph entry point
// the entry point is called by the engine when the workflow is invoked.
func depgraphWorkflowEntryPoint(invocation workflow.InvocationContext, input []workflow.Data) (depGraphList []workflow.Data, err error) {
	err = nil
	depGraphList = []workflow.Data{}

	engine := invocation.GetEngine()
	config := invocation.GetConfiguration()
	debugLogger := invocation.GetLogger()

	debugLogger.Println("depgraph workflow start")

	// prepare invocation of the legacy cli
	snykCmdArguments := []string{"test", "--print-graph", "--json"}
	if allProjects := config.GetBool("all-projects"); allProjects {
		snykCmdArguments = append(snykCmdArguments, "--all-projects")
	}

	if config.GetBool("fail-fast") {
		snykCmdArguments = append(snykCmdArguments, "--fail-fast")
	}

	if exclude := config.GetString("exclude"); exclude != "" {
		snykCmdArguments = append(snykCmdArguments, "--exclude="+exclude)
		debugLogger.Println("Exclude:", exclude)
	}

	if detectionDepth := config.GetString("detection-depth"); detectionDepth != "" {
		snykCmdArguments = append(snykCmdArguments, "--detection-depth="+detectionDepth)
		debugLogger.Println("Detection depth:", detectionDepth)
	}

	if pruneRepeatedSubDependencies := config.GetBool("prune-repeated-subdependencies"); pruneRepeatedSubDependencies {
		snykCmdArguments = append(snykCmdArguments, "--prune-repeated-subdependencies")
		debugLogger.Println("Prune repeated sub-dependencies:", pruneRepeatedSubDependencies)
	}

	if targetDirectory := config.GetString("targetDirectory"); err == nil {
		snykCmdArguments = append(snykCmdArguments, targetDirectory)
	}

	if unmanaged := config.GetBool("unmanaged"); unmanaged {
		snykCmdArguments = append(snykCmdArguments, "--unmanaged")
	}

	if file := config.GetString("file"); len(file) > 0 {
		snykCmdArguments = append(snykCmdArguments, "--file="+file)
		debugLogger.Println("File:", file)
	}

	if config.GetBool(configuration.DEBUG) {
		snykCmdArguments = append(snykCmdArguments, "--debug")
	}

	if config.GetBool("dev") {
		snykCmdArguments = append(snykCmdArguments, "--dev")
	}

	config.Set(configuration.RAW_CMD_ARGS, snykCmdArguments)
	legacyData, legacyCLIError := engine.InvokeWithConfig(workflow.NewWorkflowIdentifier("legacycli"), config)
	if legacyCLIError != nil {
		legacyCLIError = extractLegacyCLIError(legacyCLIError, legacyData)
		return depGraphList, legacyCLIError
	}

	depGraphList, err = extractDepGraphsFromCLIOutput(legacyData[0].GetPayload().([]byte))
	if err != nil {
		return nil, fmt.Errorf("could not extract depGraphs from CLI output: %w", err)
	}

	debugLogger.Printf("depgraph workflow done (%d)", len(depGraphList))

	return depGraphList, err
}

// depGraphSeparator separates the depgraph from the target name and the rest.
// The DepGraph and the name are caught in a capturing group.
//
// The `(?s)` at the beginning enables multiline-matching.
var depGraphSeparator = regexp.MustCompile(`(?s)DepGraph data:(.*?)DepGraph target:(.*?)DepGraph end`)

const depGraphContentType = "application/json"

func extractDepGraphsFromCLIOutput(output []byte) ([]workflow.Data, error) {
	if len(output) == 0 {
		return nil, noDependencyGraphsError{output}
	}

	matches := depGraphSeparator.FindAllSubmatch(output, -1)
	depGraphs := make([]workflow.Data, 0, len(matches))
	for _, match := range matches {
		if len(match) != 3 {
			return nil, fmt.Errorf("malformed CLI output, got %v matches", len(match))
		}

		data := workflow.NewData(DATATYPEID_DEPGRAPH, depGraphContentType, match[1])
		data.SetMetaData("Content-Location", strings.TrimSpace(string(match[2])))
		depGraphs = append(depGraphs, data)
	}

	return depGraphs, nil
}

type noDependencyGraphsError struct {
	output []byte
}

func (n noDependencyGraphsError) Error() string {
	return fmt.Sprintf("no dependency graphs found in output: %s", n.output)
}
