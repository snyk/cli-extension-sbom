package mocks

import (
	"net/http"
	"net/http/httptest"
)

type response struct {
	contentType string
	body        []byte
	status      int
}

func NewMockSBOMService(response response, assertions ...func(r *http.Request)) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, assert := range assertions {
			assert(r)
		}

		w.Header().Set("Content-Type", response.contentType)
		if response.status >= http.StatusContinue {
			w.WriteHeader(response.status)
		}
		if _, err := w.Write(response.body); err != nil {
			panic(err)
		}
	}))

	return ts
}

func NewMockResponse(c string, b []byte, status int) response {
	return response{
		contentType: c,
		body:        b,
		status:      status,
	}
}
