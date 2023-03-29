package extension_errors

// SBOMExtensionError represents something gone wrong during the
// execution of the CLI Extension. It holds error details, but
// serializes to a human-friendly, customer facing message.
// This is an interim solution until the integration of a generic
// error-catalog interface.
type SBOMExtensionError struct {
	err     error
	userMsg string
}

func New(err error, userMsg string) *SBOMExtensionError {
	return &SBOMExtensionError{
		err:     err,
		userMsg: userMsg,
	}
}

func (xerr SBOMExtensionError) Error() string {
	return xerr.userMsg
}

func NewInternalError(err error) *SBOMExtensionError {
	return New(
		err,
		"An error occurred while running the underlying analysis which is required to generate the SBOM. "+
			"Should this issue persist, please reach out to customer support.",
	)
}

func NewRemoteError(err error) *SBOMExtensionError {
	return New(
		err,
		"An error occurred while generating the SBOM. "+
			"Should this issue persist, please reach out to customer support.",
	)
}
