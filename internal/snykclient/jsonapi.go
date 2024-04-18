package snykclient

// JSONAPI describes a service's implementation of the JSON API specification.
type JSONAPI struct {
	Version string `json:"version"`
}

// errorDocument represents a JSON API error document.
type errorDocument struct {
	JSONAPI JSONAPI       `json:"jsonapi"`
	Errors  []errorObject `json:"errors"`
}

// errorObject represents a JSON API error object, as defined in
// https://jsonapi.org/format/#error-objects.
type errorObject struct {
	Status string `json:"status"`
	Detail string `json:"detail"`

	ID     string       `json:"id,omitempty"`
	Code   string       `json:"code,omitempty"`
	Title  string       `json:"title,omitempty"`
	Source *errorSource `json:"source,omitempty"`
	Meta   meta         `json:"meta,omitempty"`
}

// errorSource references the source of the error in the request.
type errorSource struct {
	Pointer   string `json:"pointer"`
	Parameter string `json:"parameter"`
}

// meta represents non-standard meta-information as defined in
// https://jsonapi.org/format/#document-meta.
type meta map[string]interface{}
