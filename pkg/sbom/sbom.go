package sbom

import (
	"encoding/json"
	"fmt"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"

	"github.com/snyk/cli-extension-sbom/internal/errors"
	"github.com/snyk/cli-extension-sbom/internal/service"
	"github.com/snyk/cli-extension-sbom/pkg/flag"
)

func NewWorkflow(command string, dg DepGrapher) *Workflow {
	return &Workflow{
		name:     command,
		DepGraph: dg,
		format: flag.Flag[string]{
			Name:         "format",
			Shorthand:    "f",
			Usage:        "Specify the SBOM output format. (cyclonedx1.4+json, cyclonedx1.4+xml, spdx2.3+json)",
			DefaultValue: "",
		},
	}
}

func InitWorkflow(e workflow.Engine, w *Workflow) error {
	fs := pflag.NewFlagSet(w.name, pflag.ExitOnError)
	for _, f := range w.Flags() {
		f.AddToFlagSet(fs)
	}

	_, err := e.Register(
		w.Identifier(),
		workflow.ConfigurationOptionsFromFlagset(fs),
		w.Entrypoint,
	)
	return err
}

type DepGrapher interface {
	// Metadata should return the name and version for the given configuration and depGraphs. If the
	// name is empty and only one depGraph is provided, it will be ignored. Otherwise, the metadata
	// will be set on the generated SBOM.
	Metadata(c configuration.Configuration, depGraphs []workflow.Data) (name, version string, err error)
	// invoke the subcommand that's required to generate a depGraph.
	Invoke(workflow.Engine, configuration.Configuration) ([]workflow.Data, error)
	// flags should return all flags that are required to successfully produce a depGraph and the
	// subject.
	Flags() flag.Flags
}

type Workflow struct {
	// name is the name of this workflow, e.g. how it will be invoked. For example, a name of
	// "container sbom" means that the workflow will be invoked with a "snyk container sbom" on the
	// CLI.
	name string
	// depGraph abstracts away all the container- and open-source-specific parts of generating an
	// depGraph that we can then convert to an SBOM.
	DepGraph DepGrapher

	// format of the SBOM.
	format flag.Flag[string]
}

func (w *Workflow) Flags() flag.Flags {
	return append(w.DepGraph.Flags(), w.format)
}

func (w *Workflow) Identifier() workflow.Identifier {
	return workflow.NewWorkflowIdentifier(w.name)
}

func (w *Workflow) typeIdentifier() workflow.Identifier {
	return workflow.NewTypeIdentifier(w.Identifier(), "sbom")
}

func (w *Workflow) Entrypoint(ictx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
	var (
		config     = ictx.GetConfiguration()
		logger     = ictx.GetLogger()
		format     = w.format.Value(config)
		errFactory = errors.NewErrorFactory(logger)
	)

	logger.Println("start")

	if err := service.ValidateSBOMFormat(errFactory, format); err != nil {
		return nil, err
	}

	logger.Println("Getting preferred organization ID")

	orgID := config.GetString(configuration.ORGANIZATION)
	if orgID == "" {
		return nil, errFactory.NewEmptyOrgError()
	}

	logger.Println("Invoking depgraph workflow")

	depGraphs, err := w.DepGraph.Invoke(ictx.GetEngine(), config)
	if err != nil {
		return nil, errFactory.NewDepGraphWorkflowError(err)
	}

	name, version, err := w.DepGraph.Metadata(config, depGraphs)
	if err != nil {
		return nil, errFactory.NewDepGraphWorkflowError(err)
	}
	var subject *service.Subject
	if name != "" {
		subject = service.NewSubject(name, version)
	}

	logger.Printf("Document subject: %v\n", subject)

	logger.Printf("Generating documents for %d depgraph(s)\n", len(depGraphs))
	depGraphsBytes := make([]json.RawMessage, 0, len(depGraphs))
	for _, depGraph := range depGraphs {
		// not sure if this can ever happen, but better be sure.
		if depGraph.GetPayload() == nil {
			continue
		}

		depGraphBytes, ok := depGraph.GetPayload().([]byte)
		if !ok {
			return nil, fmt.Errorf("invalid payload type (want []byte, got %T)", depGraph.GetPayload())
		}
		depGraphsBytes = append(depGraphsBytes, depGraphBytes)
	}

	result, err := service.DepGraphsToSBOM(
		ictx.GetNetworkAccess().GetHttpClient(),
		config.GetString(configuration.API_URL),
		orgID,
		depGraphsBytes,
		subject,
		format,
		logger,
		errFactory,
	)
	if err != nil {
		return nil, err
	}

	logger.Print("Successfully generated SBOM document.\n")
	return []workflow.Data{w.newDepGraphData(result)}, nil
}

func (w *Workflow) newDepGraphData(res *service.SBOMResult) workflow.Data {
	return workflow.NewDataFromInput(nil, w.typeIdentifier(), res.MIMEType, res.Doc)
}
