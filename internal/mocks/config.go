package mocks

import (
	"net/url"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/spf13/pflag"
)

type MockConfig struct {
	api string
}

func (c *MockConfig) Clone() configuration.Configuration {
	return nil
}

func (c *MockConfig) Set(key string, value interface{}) {}

func (c *MockConfig) Get(key string) interface{} {
	return nil
}

func (c *MockConfig) GetString(key string) string {
	switch key {
	case configuration.ORGANIZATION:
		return "6277734c-fc84-4c74-9662-33d46ec66c53"
	case configuration.API_URL:
		return c.api
	default:
		return ""
	}
}

func (c *MockConfig) GetBool(key string) bool {
	return false
}

func (c *MockConfig) GetInt(key string) int {
	return 0
}

func (c *MockConfig) GetFloat64(key string) float64 {
	return 0
}

func (c *MockConfig) GetUrl(key string) *url.URL {
	return nil
}

func (c *MockConfig) AddFlagSet(flagset *pflag.FlagSet) error {
	return nil
}

func NewMockConfig(apiURL string) *MockConfig {
	return &MockConfig{
		api: apiURL,
	}
}
