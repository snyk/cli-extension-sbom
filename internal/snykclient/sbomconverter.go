//nolint:lll // Long lined example dep-graphs will be removed in the future.
package snykclient

import (
	"context"
	"encoding/json"

	"github.com/snyk/cli-extension-sbom/internal/errors"
)

const targetName = "SBOM Monitor Spike v2"

const pubProjectJSON = `
{
	"name": "Dart project",
	"policy": "\n",
	"facts": [{
		"type": "depGraph",
		"data": {"schemaVersion":"1.2.0","pkgManager":{"name":"pub"},"pkgs":[{"id":"my-project@0.0.0","info":{"name":"my-project","version":"0.0.0"}},{"id":"pubnub@1.0.0","info":{"name":"pubnub","version":"1.0.0"}}],"graph":{"rootNodeId":"root-node","nodes":[{"nodeId":"root-node","pkgId":"my-project@0.0.0","deps":[{"nodeId":"pubnub@1.0.0"}]},{"nodeId":"pubnub@1.0.0","pkgId":"pubnub@1.0.0","deps":[]}]}}
	}],
	"target": { "name": "` + targetName + `" },
	"identity": { "type": "pub" }
}
`

const npmProjectJSON = `
{
	"name": "simple npm vuln project",
	"policy": "\n",
	"facts": [{
		"type": "depGraph",
		"data": {"schemaVersion":"1.3.0","pkgManager":{"name":"npm"},"pkgs":[{"id":"my-great-project@1.0.0","info":{"name":"my-great-project","version":"1.0.0","purl":"pkg:npm/my-great-project@1.0.0"}},{"id":"minimatch@3.0.4","info":{"name":"minimatch","version":"3.0.4","purl":"pkg:npm/minimatch@3.0.4"}},{"id":"brace-expansion@1.1.11","info":{"name":"brace-expansion","version":"1.1.11","purl":"pkg:npm/brace-expansion@1.1.11"}},{"id":"balanced-match@1.0.2","info":{"name":"balanced-match","version":"1.0.2","purl":"pkg:npm/balanced-match@1.0.2"}},{"id":"concat-map@0.0.1","info":{"name":"concat-map","version":"0.0.1","purl":"pkg:npm/concat-map@0.0.1"}}],"graph":{"rootNodeId":"root-node","nodes":[{"nodeId":"concat-map@0.0.1","pkgId":"concat-map@0.0.1","deps":[]},{"nodeId":"root-node","pkgId":"my-great-project@1.0.0","deps":[{"nodeId":"minimatch@3.0.4"}]},{"nodeId":"minimatch@3.0.4","pkgId":"minimatch@3.0.4","deps":[{"nodeId":"brace-expansion@1.1.11"}]},{"nodeId":"brace-expansion@1.1.11","pkgId":"brace-expansion@1.1.11","deps":[{"nodeId":"balanced-match@1.0.2"},{"nodeId":"concat-map@0.0.1"}]},{"nodeId":"balanced-match@1.0.2","pkgId":"balanced-match@1.0.2","deps":[]}]}}
	}],
	"target": { "name": "` + targetName + `" },
	"identity": { "type": "npm" }
}
`

func (t *SnykClient) ConvertSBOM(
	ctx context.Context,
	errFactory *errors.ErrorFactory,
	sbomBytes []byte,
	filename string,
) ([]ScanResult, error) {
	var pubProject ScanResult
	err := json.Unmarshal([]byte(pubProjectJSON), &pubProject)
	if err != nil {
		return nil, err
	}

	var npmProject ScanResult
	err = json.Unmarshal([]byte(npmProjectJSON), &npmProject)
	if err != nil {
		return nil, err
	}

	return []ScanResult{pubProject, npmProject}, nil
}
