package workflowerrors

// WorkflowError is a CLI Extension specific error which gets
// returned to the caller of a workflow. It distinguishes between
// the internal technical error, and a customer facing error
// message.
type WorkflowError struct {
	err error
	msg string
}

// Error returns the user-facing error message.
func (e WorkflowError) Error() string {
	return e.msg
}

// GetError returns the internal error instance.
func (e WorkflowError) GetError() error {
	return e.err
}

func NewWorkflowError(e error, msg string) WorkflowError {
	return WorkflowError{
		err: e,
		msg: msg,
	}
}
