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

func (ef *ErrorFactory) NewInternalError(err error) *SBOMExtensionError {
	return ef.newErr(
		err,
		"An error occurred while running the underlying analysis which is required to generate the SBOM. "+
			"Should this issue persist, please reach out to customer support.",
	)
}

func (ef *ErrorFactory) NewRemoteError(err error) *SBOMExtensionError {
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

func (ef *ErrorFactory) NewBadRequestError(err error) *SBOMExtensionError {
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
