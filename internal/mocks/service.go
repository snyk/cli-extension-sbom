package mocks

import (
	"net/http"
	"net/http/httptest"
)

func NewMockSBOMService(response []byte) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.cyclonedx+json")
		if _, err := w.Write(response); err != nil {
			panic(err)
		}
	}))

	return ts
}
