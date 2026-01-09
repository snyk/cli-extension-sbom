package sbomcreate_test

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-sbom/internal/commands/sbomcreate"
)

func TestResolveSubjectNameFromPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
		platform string // If present, only run test on this platform
	}{
		{
			name:     "normal directory",
			path:     "/Users/test/my-project-1",
			expected: "my-project-1",
		},
		{
			name:     "Unix root directory",
			path:     "/",
			expected: "project",
		},
		{
			name:     "Windows root directory G",
			path:     "G:\\",
			expected: "G:",
			platform: "windows",
		},
		{
			name:     "empty path",
			path:     "",
			expected: "project",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sbomcreate.ResolveSubjectNameFromPath(tt.path)
			if tt.platform == "" || tt.platform == runtime.GOOS {
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}
