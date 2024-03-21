package snykclient

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func parseResponse(rsp *http.Response, expectedStatusCode int, expectedDocument interface{}) error {
	body, err := io.ReadAll(rsp.Body)
	defer rsp.Body.Close()
	if err != nil {
		return err
	}

	if rsp.StatusCode != expectedStatusCode {
		var errorDoc errorDocument
		if err := json.Unmarshal(body, &errorDoc); err != nil {
			// If the error is not encoded as JSON, that is less important a detail to
			// surface to the user than the actual content of the error. Notably, this
			// can occur when cerberus bounces the request, as it returns plain text
			// bodies.
			return fmt.Errorf("response %d: %s", rsp.StatusCode, string(body))
		}
		return fmt.Errorf("%s", errorDocumentToString(errorDoc))
	}
	if expectedDocument != nil {
		return json.Unmarshal(body, expectedDocument)
	}
	return nil
}

func errorDocumentToString(err errorDocument) string {
	msgs := []string{}
	if len(err.Errors) == 0 {
		msgs = append(msgs, "unknown error")
	} else {
		for i := range err.Errors {
			msgs = append(msgs, errorObjectToString(&err.Errors[i]))
		}
	}
	return strings.Join(msgs, "\n")
}

func errorObjectToString(err *errorObject) string {
	return fmt.Sprintf("%s %s: %s", err.Status, err.Title, err.Detail)
}
