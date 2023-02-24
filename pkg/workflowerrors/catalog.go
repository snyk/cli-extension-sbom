package workflowerrors

import "errors"

func NewExperimentalFlagError() WorkflowError {
	return NewWorkflowError(
		errors.New("experimental flag not set"),
		"Please set the `--experimental` flag to enable running the `sbom` command.",
	)
}

func NewEmptyOrgIDError() WorkflowError {
	return NewWorkflowError(
		errors.New("empty org ID"),
		"Automatic detection of your org ID failed. Please supply an org ID by setting the `--org` flag.",
	)
}

func NewFailedSCAError(err error) WorkflowError {
	return NewWorkflowError(
		err,
		`We failed to detect a project or the dependencies for the detected project.
		Please run with -d flag to debug or get in touch with customer support.`,
	)
}

func NewFailedConversionError(err error) WorkflowError {
	// TODO: check about authz/authn issues and give a different
	// result depending on the error case.
	return NewWorkflowError(
		err,
		`The conversion of the SCA result to an SBOM failed.`,
	)
}
