package depgraph

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/snyk/cli-extension-sbom/pkg/flag"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
)

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
	// if there's no data, we can't extract anything.
	if len(data) == 0 {
		return input
	}

	// extract error from legacy cli if possible and wrap it in an error instance
	var exitErr *exec.ExitError
	if errors.As(input, &exitErr) {
		bytes, ok := data[0].GetPayload().([]byte)
		if !ok {
			return output
		}

		var decodedError legacyCLIJSONError
		if json.Unmarshal(bytes, &decodedError) == nil {
			return &decodedError
		}
	}
	return input
}

func NewWorkflow[T workflowConfig](cmd string, subWorkflow T) *Workflow[T] {
	return &Workflow[T]{
		Name: cmd,
		Config: Config[T]{
			Debug:      flag.Flag[bool]{Name: configuration.DEBUG, DefaultValue: false},
			SubCommand: subWorkflow,
		},
	}
}

// InitDepGraphWorkflow initializes the depgraph workflow
// The depgraph workflow is responsible for handling the depgraph data
// As part of the localworkflows package, it is registered via the localworkflows.Init method.
func InitWorkflow[T workflowConfig](engine workflow.Engine, w *Workflow[T]) error {
	fs := pflag.NewFlagSet(w.Name, pflag.ExitOnError)
	for _, f := range w.Flags() {
		f.AddToFlagSet(fs)
	}

	_, err := engine.Register(w.Identifier(), workflow.ConfigurationOptionsFromFlagset(fs), w.Entrypoint)
	return err
}

type workflowConfig interface {
	Command() []string
	Flags() flag.Flags
}

type Workflow[c workflowConfig] struct {
	Name string
	Config[c]
}

func (w Workflow[Config]) Identifier() workflow.Identifier {
	return workflow.NewWorkflowIdentifier(w.Name)
}

func (w Workflow[Config]) TypeIdentifier() workflow.Identifier {
	return workflow.NewTypeIdentifier(w.Identifier(), "depgraph")
}

var legacyCLIID = workflow.NewWorkflowIdentifier("legacycli")

func (w Workflow[Config]) Entrypoint(invocation workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	debugLogger := invocation.GetLogger()
	debugLogger.Printf("start")

	cmdArgs := w.SubCommand.Command()
	config := invocation.GetConfiguration()
	for _, flag := range w.Flags() {
		if arg, ok := flag.AsArgument(config); ok {
			cmdArgs = append(cmdArgs, arg)
		}
	}

	// This is the directory for OS, or the container name for container. It's not a flag, but a
	// positional argument.
	cmdArgs = append(cmdArgs, config.GetString("targetDirectory"))
	debugLogger.Printf("cli invocation args: %v", cmdArgs)

	config.Set(configuration.RAW_CMD_ARGS, cmdArgs)
	data, err := invocation.GetEngine().InvokeWithConfig(legacyCLIID, config)
	if err != nil {
		return nil, extractLegacyCLIError(err, data)
	}

	depGraphList, err := w.extractDepGraphsFromCLIOutput(data[0].GetPayload().([]byte))
	if err != nil {
		return nil, fmt.Errorf("could not extract depGraphs from CLI output: %w", err)
	}

	debugLogger.Printf("done (%d)", len(depGraphList))

	return depGraphList, nil
}

type Config[specific workflowConfig] struct {
	Debug      flag.Flag[bool]
	SubCommand specific
}

func (c Config[a]) Flags() flag.Flags {
	return append(c.SubCommand.Flags(), c.Debug)
}

// depGraphSeparator separates the depgraph from the target name and the rest.
// The DepGraph and the name are caught in a capturing group.
//
// The `(?s)` at the beginning enables multiline-matching.
var depGraphSeparator = regexp.MustCompile(`(?s)DepGraph data:(.*?)DepGraph target:(.*?)DepGraph end`)

const depGraphContentType = "application/json"

func (w Workflow[Config]) extractDepGraphsFromCLIOutput(output []byte) ([]workflow.Data, error) {
	if len(output) == 0 {
		return nil, noDependencyGraphsError{output}
	}

	matches := depGraphSeparator.FindAllSubmatch(output, -1)
	depGraphs := make([]workflow.Data, 0, len(matches))
	for _, match := range matches {
		if len(match) != 3 {
			return nil, fmt.Errorf("malformed CLI output, got %v matches", len(match))
		}

		data := workflow.NewData(w.TypeIdentifier(), depGraphContentType, match[1])
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
