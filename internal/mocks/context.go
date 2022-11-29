package mocks

import (
	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

type MockInvocationContext struct {
	e workflow.Engine
	c configuration.Configuration
}

func (ictx *MockInvocationContext) GetWorkflowIdentifier() workflow.Identifier {
	return nil
}

func (ictx *MockInvocationContext) GetConfiguration() configuration.Configuration {
	return ictx.c
}

func (ictx *MockInvocationContext) GetEngine() workflow.Engine {
	return ictx.e
}

func (ictx *MockInvocationContext) GetAnalytics() analytics.Analytics {
	return nil
}

func (ictx *MockInvocationContext) GetNetworkAccess() networking.NetworkAccess {
	return nil
}

func NewMockInvocationContext(e workflow.Engine, c configuration.Configuration) MockInvocationContext {
	ictx := MockInvocationContext{e, c}
	return ictx
}
