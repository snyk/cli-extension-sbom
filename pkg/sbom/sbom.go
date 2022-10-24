package sbom

import (
	"net/url"

	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
)

var WorkflowID workflow.Identifier

func Init(e workflow.Engine) error {
	WorkflowID, _ = url.Parse("flw://sbom")

	flagset := pflag.NewFlagSet("snyk-cli-extension-sbom", pflag.ExitOnError)
	// TODO
	flagset.String("file", "", "TODO: usage docs for file option")
	// TODO
	flagset.StringP("format", "f", "text", "TODO: usage docs for format option")

	c := workflow.ConfigurationOptionsFromFlagset(flagset)

	if _, err := e.Register(WorkflowID, c, SBOMWorkflow); err != nil {
		return err
	}

	return nil
}

func SBOMWorkflow(
	invocation workflow.InvocationContext,
	input []workflow.Data,
) (data []workflow.Data, err error) {
	// TODO: implement SBOM workflow
	// get engine from invocation context
	// invoke dep graph workflow
	// process result
	return data, err
}
