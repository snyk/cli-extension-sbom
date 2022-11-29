package mocks

import (
	_ "embed"
	"errors"

	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

//go:embed testdata/depgraph.json
var depGraphBytes []byte

type MockEngine struct{}

func (e *MockEngine) Init() error {
	return nil
}

func (e *MockEngine) Register(id workflow.Identifier, config workflow.ConfigurationOptions, callback workflow.Callback) (workflow.Entry, error) {
	return nil, nil
}

func (e *MockEngine) GetWorkflows() []workflow.Identifier {
	return []workflow.Identifier{}
}

func (e *MockEngine) GetWorkflow(id workflow.Identifier) (workflow.Entry, bool) {
	return nil, false
}

func (e *MockEngine) Invoke(id workflow.Identifier) ([]workflow.Data, error) {
	if id.String() == "flw://depgraph" {
		data := workflow.NewData(id, "application/json", depGraphBytes)
		return []workflow.Data{data}, nil
	}
	return nil, errors.New("workflow not mocked")
}

func (e *MockEngine) InvokeWithInput(id workflow.Identifier, input []workflow.Data) ([]workflow.Data, error) {
	return nil, nil
}

func (e *MockEngine) GetAnalytics() analytics.Analytics {
	return nil
}

func (e *MockEngine) GetNetworkAccess() networking.NetworkAccess {
	return nil
}

func NewMockEngine() workflow.Engine {
	return &MockEngine{}
}
