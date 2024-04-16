package errors

import (
	"fmt"
	"log"
	"strings"
)

// SBOMExtensionError represents something gone wrong during the
// execution of the CLI Extension. It holds error details, but
// serializes to a human-friendly, customer facing message.
// This is an interim solution until the integration of a generic
// error-catalog interface.
type SBOMExtensionError struct {
	err     error
	userMsg string
}

func (xerr SBOMExtensionError) Error() string {
	return xerr.userMsg
}

type ErrorFactory struct {
	logger *log.Logger
}

func NewErrorFactory(logger *log.Logger) *ErrorFactory {
	return &ErrorFactory{
		logger: logger,
	}
}

func (ef *ErrorFactory) newErr(err error, userMsg string) *SBOMExtensionError {
	ef.logger.Printf("ERROR: %s\n", err)

	return &SBOMExtensionError{
		err:     err,
		userMsg: userMsg,
	}
}

func (ef *ErrorFactory) NewFatalSBOMGenerationError(err error) *SBOMExtensionError {
	return ef.newErr(
		err,
		"An error occurred while running the underlying analysis which is required to generate the SBOM. "+
			"Should this issue persist, please reach out to customer support.",
	)
}

func (ef *ErrorFactory) NewRemoteGenerationError(err error) *SBOMExtensionError {
	return ef.newErr(
		err,
		"An error occurred while generating the SBOM. "+
			"Should this issue persist, please reach out to customer support.",
	)
}

func (ef *ErrorFactory) NewEmptyOrgError() *SBOMExtensionError {
	return ef.newErr(
		fmt.Errorf("failed to determine org id"),
		"Snyk failed to infer an organization ID. Please make sure to authenticate using `snyk auth`. "+
			"Should the issue persist, explicitly set an organization ID via the `--org` flag.",
	)
}

func (ef *ErrorFactory) NewDepGraphWorkflowError(err error) *SBOMExtensionError {
	return ef.newErr(
		fmt.Errorf("error while invoking depgraph workflow: %w", err),
		"An error occurred while running the underlying analysis needed to generate the SBOM.",
	)
}

func (ef *ErrorFactory) NewEmptyFormatError(available []string) *SBOMExtensionError {
	return ef.newErr(
		fmt.Errorf("no format provided"),
		fmt.Sprintf(
			"Must set `--format` flag to specify an SBOM format. "+
				"Available formats are: %s",
			strings.Join(available, ", "),
		),
	)
}

func (ef *ErrorFactory) NewInvalidFormatError(invalid string, available []string) *SBOMExtensionError {
	return ef.newErr(
		fmt.Errorf("invalid format provided (%s)", invalid),
		fmt.Sprintf(
			"The format provided (%s) is not one of the available formats. "+
				"Available formats are: %s",
			invalid,
			strings.Join(available, ", "),
		),
	)
}

func (ef *ErrorFactory) NewBadRequestGenerationError(err error) *SBOMExtensionError {
	return ef.newErr(
		err,
		"SBOM generation failed due to bad input arguments. "+
			"Please make sure you are using the latest version of the Snyk CLI.",
	)
}

func (ef *ErrorFactory) NewUnauthorizedError(err error) *SBOMExtensionError {
	return ef.newErr(
		err,
		"Snyk failed to authenticate you based on on you API token. "+
			"Please ensure that you have authenticated by running `snyk auth`.",
	)
}

func (ef *ErrorFactory) NewForbiddenError(err error, orgID string) *SBOMExtensionError {
	return ef.newErr(
		err,
		fmt.Sprintf(
			"Your account is not authorized to perform this action. "+
				"Please ensure that you belong to the given organization and that "+
				"the organization is entitled to use the Snyk API. (Org ID: %s)",
			orgID,
		),
	)
}

func (ef *ErrorFactory) IndeterminateWorkingDirectory(err error) *SBOMExtensionError {
	return ef.newErr(
		err,
		"Snyk failed to infer a working directory. Should the issue persist,"+
			" explicitly set an name via the `--name` flag.",
	)
}

func (ef *ErrorFactory) NewMissingExperimentalFlagError() *SBOMExtensionError {
	return ef.newErr(
		fmt.Errorf("exmperimental flag not set"),
		"Flag `--experimental` is required to execute this command.",
	)
}

func (ef *ErrorFactory) NewMissingFilenameFlagError() *SBOMExtensionError {
	return ef.newErr(
		fmt.Errorf("file flag not set"),
		"Flag `--file` is required to execute this command. Value should point to a valid SBOM document.",
	)
}

func (ef *ErrorFactory) NewFailedToReadFileError(err error) *SBOMExtensionError {
	return ef.newErr(
		err,
		"failed to read file",
	)
}

func (ef *ErrorFactory) NewFileIsDirectoryError() *SBOMExtensionError {
	return ef.newErr(
		fmt.Errorf("file is a directory"),
		"The path provided points to a directory. Please ensure the `--file` flag value is pointing to a file.",
	)
}

func (ef *ErrorFactory) NewInvalidJSONError() *SBOMExtensionError {
	return ef.newErr(
		fmt.Errorf("file is not valid JSON"),
		"The file provided by the `--file` flag is not valid JSON.",
	)
}

func (ef *ErrorFactory) NewFailedToTestSBOMError() *SBOMExtensionError {
	return ef.NewFatalSBOMTestError(fmt.Errorf("failed to test SBOM"))
}

func (ef *ErrorFactory) NewFatalSBOMTestError(err error) *SBOMExtensionError {
	return ef.newErr(
		err,
		"Failed to test SBOM. There was an error when trying to test your SBOM,"+
			"retrying may resolve the issue. If the error still occurs, contact support.",
	)
}
