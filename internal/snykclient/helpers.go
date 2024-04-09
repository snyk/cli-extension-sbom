package snykclient

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/snyk/cli-extension-sbom/internal/errors"
)

func parseResponse(rsp *http.Response, expectedStatusCode int, expectedDocument interface{}, errFactory *errors.ErrorFactory) error {
	body, err := io.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return err
	}

	if rsp.StatusCode != expectedStatusCode {
		var errorDoc errorDocument
		if err = json.Unmarshal(body, &errorDoc); err != nil {
			// If the error is not encoded as JSON, that is less important a detail to
			// surface to the user than the actual content of the error. Notably, this
			// can occur when cerberus bounces the request, as it returns plain text
			// bodies.
			return errFactory.NewInternalError(err)
		}
		return errFactory.NewInternalError(err)
	}
	if expectedDocument != nil {
		return json.Unmarshal(body, expectedDocument)
	}
	return nil
}
