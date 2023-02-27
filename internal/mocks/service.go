package mocks

import (
	"net/http"
	"net/http/httptest"
)

type response struct {
	contentType string
	body        []byte
}

func NewMockSBOMService(response response, assertions ...func(r *http.Request)) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, assert := range assertions {
			assert(r)
		}

		w.Header().Set("Content-Type", response.contentType)
		if _, err := w.Write(response.body); err != nil {
			panic(err)
		}
	}))

	return ts
}

func NewMockResponse(c string, b []byte) response {
	return response{
		contentType: c,
		body:        b,
	}
}
