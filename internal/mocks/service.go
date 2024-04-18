package mocks

import (
	"net/http"
	"net/http/httptest"
)

type MockResponse struct {
	contentType string
	body        []byte
	status      int
	headers     http.Header
}

func NewMockSBOMService(resp MockResponse, assertions ...func(r *http.Request)) *httptest.Server {
	responses := []MockResponse{resp}

	return NewMockSBOMServiceMultiResponse(responses, assertions...)
}

func NewMockSBOMServiceMultiResponse(responses []MockResponse, assertions ...func(r *http.Request)) *httptest.Server {
	var responseIndex int

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if responseIndex >= len(responses) {
			panic("unexpected request")
		}
		resp := responses[responseIndex]

		for _, assert := range assertions {
			assert(r)
		}

		w.Header().Set("Content-Type", resp.contentType)
		for k, values := range resp.headers {
			for _, v := range values {
				w.Header().Set(k, v)
			}
		}

		if resp.status >= http.StatusContinue {
			w.WriteHeader(resp.status)
		}

		if _, err := w.Write(resp.body); err != nil {
			panic(err)
		}

		responseIndex++
	}))

	return ts
}

func NewMockResponse(c string, b []byte, status int) MockResponse {
	return MockResponse{
		contentType: c,
		body:        b,
		status:      status,
		headers:     http.Header{},
	}
}

func NewMockResponseWithHeaders(c string, b []byte, status int, headers http.Header) MockResponse {
	return MockResponse{
		contentType: c,
		body:        b,
		status:      status,
		headers:     headers,
	}
}
