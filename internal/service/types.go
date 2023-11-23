package service

import "encoding/json"

type Tool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type payloadSingleDepGraph struct {
	Tools    []*Tool         `json:"tools,omitempty"`
	DepGraph json.RawMessage `json:"depGraph"`
}

type payloadMultipleDepGraphs struct {
	Tools     []*Tool           `json:"tools,omitempty"`
	DepGraphs []json.RawMessage `json:"depGraphs"`
	Subject   *Subject          `json:"subject"`
}
