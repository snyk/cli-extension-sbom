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
